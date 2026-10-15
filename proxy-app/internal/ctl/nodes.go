package ctl

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 多线路（多实例）：落地节点登记表 + 给节点用的几个接口。
//
// 拓扑：
//
//	客户端 ──登录──► 本机（总节点，唯一控制面）
//	  通道A：客户端 ──REALITY──► 落地节点（分支节点A）──► 外网
//	  通道B：客户端 ──QUIC──────► 落地节点（分支节点A）──► 外网
//
// **落地节点自己出网**：用户要的效果是「从分支节点A的 IP 访问互联网」，所以数据面
// 不经过本机。两台机器之间只有控制面 —— 节点上报自身、领走「被授权用它的」账号
// 参数、再把流量与访问记录报回来汇总。
//
// 三条设计取舍值得说明：
//
//  1. **让节点主动上报，而不是运维手抄参数**。节点的 REALITY 公钥与 shortId 是
//     它自己生成的（见 ensureNodeIdentity），抄到本机时抄错一个字符，现象只是
//     「客户端连不上」，排查代价很高。让节点启动时自己报一遍，这类人工错误就没了。
//
//  2. **认证参数不在本机留第二份副本**。线路表下发时用的就是登记表里的内容，
//     不会出现「某处缓存了一份旧的公钥」这种两边不一致的问题。
//
//  3. **密码哈希走单独一个接口**（handleNodeHashes）。它只服务通道B，而通道A
//     只需要 UUID —— 混在一起会让「只想跑通道A 的节点」也拿到哈希。

// 线路角色，取值必须与客户端 common.RoleExit / common.RoleRelay 一致。
//
// 当前拓扑下**下发的永远是 roleExit**：每个实例都是自己的出口。
// roleRelay 留着不删，是因为它是 wire 上的合法取值、客户端也仍能渲染它
// （`common.Instance.IsRelay`）—— 以后若真出现「第一跳 + 出口在别处」的形态，
// 不必再改协议。删掉它反而会让那个取值变成「客户端认识、服务端造不出来」的悬空值。
const (
	roleExit  = "exit"
	roleRelay = "relay"
)

// defaultRelayPort 是节点没上报端口时的兜底（REALITY 惯例端口）。
const defaultRelayPort = 443

// RelayNode 是一个已登记的中转节点。
type RelayNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Token 是该节点用来向本机认证自己的口令，一个节点一把：
	// 泄漏只影响这一个节点（可单独轮换），不会殃及其它节点。
	Token string `json:"token"`

	// 以下字段由节点上报时带上来，运维不需要手填。
	Address     string `json:"address,omitempty"`
	Port        int    `json:"port,omitempty"`
	SNI         string `json:"sni,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Flow        string `json:"flow,omitempty"`

	// RegisteredAt 是最后一次收到上报的时间（Unix 秒），0 表示从未上报过。
	RegisteredAt int64 `json:"registeredAt,omitempty"`
}

// Ready 报告这条登记项的参数是否已经齐到能下发给客户端。
//
// 参数不全时**不下发**：给了客户端也只会是一条连不上的线路，
// 还不如让它暂时不出现在下拉框里。
func (n RelayNode) Ready() bool {
	return n.ID != "" && n.Name != "" && n.Address != "" &&
		n.PublicKey != "" && n.ShortID != "" && n.Fingerprint != ""
}

// RelayRegistry 是中转节点登记表，落在 nodes.json。
type RelayRegistry struct {
	path  string
	mu    sync.Mutex
	Nodes []RelayNode `json:"nodes"`
}

// LoadRelayRegistry 读取登记表。文件不存在时返回空表 —— 单节点部署就是这个状态。
func LoadRelayRegistry(path string) (*RelayRegistry, error) {
	r := &RelayRegistry{path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("读取节点登记表失败: %w", err)
	}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, fmt.Errorf("节点登记表不是合法 JSON: %w", err)
	}
	return r, nil
}

// Snapshot 返回登记表的副本。接收者为 nil（没启用中转）时返回空。
func (r *RelayRegistry) Snapshot() []RelayNode {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RelayNode, len(r.Nodes))
	copy(out, r.Nodes)
	return out
}

// Authenticate 校验节点的 id 与口令。
//
// 用 constant-time 比较：这是公网接口，逐字节提前返回会把口令的长度与前缀
// 一点点泄漏出去。口令本身是 32 字节随机串，穷举不可行，所以不需要再叠加限速。
func (r *RelayRegistry) Authenticate(id, token string) bool {
	if r == nil || id == "" || token == "" {
		return false
	}
	id, token = strings.TrimSpace(id), strings.TrimSpace(token)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.Nodes {
		if n.ID != id {
			continue
		}
		return subtle.ConstantTimeCompare([]byte(n.Token), []byte(token)) == 1
	}
	return false
}

// UpsertReport 用节点上报的内容更新登记项。
//
// 只更新「节点自己能决定」的字段：显示名与口令仍以本机配置为准 ——
// 否则一个被攻陷的节点就能改掉自己的显示名（在用户的下拉框里冒充别的线路），
// 也能顺手把口令换掉让自己永久有效。
func (r *RelayRegistry) UpsertReport(id string, rep RelayNode) error {
	if r == nil {
		return fmt.Errorf("本机未启用中转节点登记")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.Nodes {
		if r.Nodes[i].ID != id {
			continue
		}
		r.Nodes[i].Address = rep.Address
		r.Nodes[i].Port = rep.Port
		r.Nodes[i].SNI = rep.SNI
		r.Nodes[i].PublicKey = rep.PublicKey
		r.Nodes[i].ShortID = rep.ShortID
		r.Nodes[i].Fingerprint = rep.Fingerprint
		r.Nodes[i].Flow = rep.Flow
		r.Nodes[i].RegisteredAt = time.Now().Unix()
		return r.saveLocked()
	}
	return fmt.Errorf("未登记的节点 id: %s", id)
}

func (r *RelayRegistry) saveLocked() error {
	if r.path == "" {
		return nil
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	// 0600：文件里有节点口令。
	return os.WriteFile(r.path, out, 0o600)
}

// NodeInstance 是下发给客户端的一条线路。
//
// 字段形状必须与客户端的 common.Instance 完全一致。之所以两边各定义一份：
// internal/common 是 Windows 专属包（直接 import golang.org/x/sys/windows），
// 服务端在 Linux 上根本编译不了它。两边的一致性由 nodes_windows_test.go 的
// 契约测试守着 —— 只改一边会立刻测出来。
type NodeInstance struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role,omitempty"`
	// Via 是「这条线路最终从哪条线路出网」，只对 relay 线路有意义。
	// 当前拓扑下**一直是空的**（每条线路自己出网），留着与客户端的字段对齐。
	Via string `json:"via,omitempty"`

	// 内嵌使 JSON 保持扁平：客户端拿到的每一项，字段形状与原来的 params 一致，
	// 于是「按线路取参数」只换一个来源，客户端其余代码一行都不用动。
	Params
}

// Instances 组装下发给客户端的线路表：本机线路排第一，其后是**该账号被授权使用**的落地线路。
//
// 授权值由调用方传进来（而不是在这里读账号）：登录与取参数两条路径都有 User 在手，
// 把过滤条件收在一处，避免以后漏改一处就悄悄变成「谁都能用」。
//
// 落地线路的**通道B 端口与混淆口令直接复用本机那份**：分支节点A跑的 hysteria 用的是同一套
// 端口与混淆口令（参数由本机下发，两边必须一致），只有证书是借用本机的域名证书。
// 因此唯一必须显式改的是 SNI：客户端连的是落地节点的地址，而证书是出口域名的，
// 不单独指定就会拿落地节点的 IP 去校验证书，必然失败（见 common.Params.HysteriaSNI）。
func (s *Service) Instances(allowed []string) ([]NodeInstance, error) {
	local, err := s.Settings.ClientParams()
	if err != nil {
		return nil, err
	}
	out := []NodeInstance{{
		ID: s.localNodeID(), Name: s.localNodeName(), Role: roleExit, Params: local,
	}}
	for _, n := range s.Relays.Snapshot() {
		if !n.Ready() || !containsID(allowed, n.ID) {
			continue
		}
		port := n.Port
		if port == 0 {
			port = defaultRelayPort
		}
		p := local // 先复制本机的通道B 参数，再覆盖入口相关的字段
		p.Address = n.Address
		p.Port = port
		p.SNI = n.SNI
		p.PublicKey = n.PublicKey
		p.ShortID = n.ShortID
		p.Fingerprint = n.Fingerprint
		p.Flow = n.Flow
		p.HysteriaSNI = local.Address
		// Role 是 exit，**不带 Via**：每个实例都是自己的出口 —— 用户要的效果是
		// 「从分支节点A的 IP 访问互联网」，这条线路不是通往别处的第一跳。
		//
		// 这里以前填的是 relay + via=core（「中转到总节点」那个已废弃方案留下的），
		// 后果是客户端把它显示成「入口 203.0.113.8 · 经中转出网」：在现拓扑下这是错的，
		// 而且正好会把用户绕回那个已经被否掉的方案。
		out = append(out, NodeInstance{
			ID: n.ID, Name: n.Name, Role: roleExit, Params: p,
		})
	}
	return out, nil
}

func containsID(list []string, id string) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// IDs 返回已登记的中转线路 id（包含还没上报过、暂时不下发的那几个），
// 供管理接口校验授权值。
func (r *RelayRegistry) IDs() []string {
	out := []string{}
	for _, n := range r.Snapshot() {
		if n.ID != "" {
			out = append(out, n.ID)
		}
	}
	return out
}

// Has 报告某个线路 id 是否已登记。
func (r *RelayRegistry) Has(id string) bool {
	for _, n := range r.Snapshot() {
		if n.ID == id {
			return true
		}
	}
	return false
}

// NormalizeAllowNodes 校验并规范化一份「授权线路」列表。
//
// 之所以要校验而不是照单全收：授权值写错（把 edge-a 写成 edge-ax）不会报任何错，
// 只会静默地变成「授了权但用不了」—— 这种问题在管理界面上极难看出来。
// 另外顺手去重，让存储内容稳定（免得同一条线路存成两份）。
func (r *RelayRegistry) NormalizeAllowNodes(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if !r.Has(id) {
			known := r.IDs()
			if len(known) == 0 {
				return nil, fmt.Errorf("本机还没有登记任何中转线路，无法授权 %q", id)
			}
			return nil, fmt.Errorf("未知的线路 id %q（已登记的有：%s）", id, strings.Join(known, "、"))
		}
		if !containsID(out, id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// localNodeID / localNodeName 是本机线路的标识与显示名。
// 显示名会出现在客户端的线路下拉框里，由服务端下发 —— 改名不用重发客户端。
func (s *Service) localNodeID() string {
	if s.Settings.NodeID != "" {
		return s.Settings.NodeID
	}
	return "local"
}

func (s *Service) localNodeName() string {
	if s.Settings.NodeName != "" {
		return s.Settings.NodeName
	}
	return "默认线路"
}

// nodeReport 是中转节点上报的内容。
type nodeReport struct {
	ID          string `json:"id"`
	Token       string `json:"token"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
	Flow        string `json:"flow"`
}

// handleNodeRegister 收下落地节点的上报，并存进登记表。
//
// 上报里带的是「节点自己能决定」的入口参数（地址/端口/伪装域名/公钥/shortId）。
// 存下来之后随登录响应下发给客户端，运维就不用手抄 —— 手抄错一个字符的现象只是
// 「客户端连不上」，而那种问题在远端机器上极难反查。
//
// 刻意**不回**任何参数：落地节点自己出网，不需要出口的任何东西。
// 早先的「中转到出口」方案会在这里把出口参数发回去，那个方案已废弃。
func (s *Service) handleNodeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	var req nodeReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}
	if !s.Relays.Authenticate(req.ID, req.Token) {
		errJSON(w, 401, "节点认证失败")
		return
	}
	if strings.TrimSpace(req.Address) == "" {
		errJSON(w, 400, "上报内容缺少 address")
		return
	}
	if err := s.Relays.UpsertReport(req.ID, RelayNode{
		Address: req.Address, Port: req.Port, SNI: req.SNI,
		PublicKey: req.PublicKey, ShortID: req.ShortID,
		Fingerprint: req.Fingerprint, Flow: req.Flow,
	}); err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	s.Log("落地节点 %s 已上报入口 %s:%d", req.ID, req.Address, req.Port)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// nodeUser 是一个账号在校验名单里的最小表示。
type nodeUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// handleNodeUsers 把账号列表发给中转节点。
//
// **这里是授权真正生效的地方**：只发「被授权使用这个节点」的账号，于是没授权的
// UUID 压根不会出现在中转节点的内核配置里，那个账号在中转节点上连认证都过不了。
// 只在登录响应里藏起线路是不够的 —— 客户端手上已经有账号密码，完全可以自己去连。
//
// 内容只给**渲染内核配置所必需的最小集**：名称与 UUID。密码哈希、流量、备注一概不给。
//
// 返回的 revision 让节点能判断「账号集合有没有变」，没变就不重载内核，
// 否则每次轮询都会把走中转线路的连接断一次。
func (s *Service) handleNodeUsers(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.Header.Get("X-Node-Id"))
	if !s.Relays.Authenticate(nodeID, r.Header.Get("X-Node-Token")) {
		errJSON(w, 401, "节点认证失败")
		return
	}
	all := s.Store.List()
	users := make([]nodeUser, 0, len(all))
	for _, u := range all {
		if !u.Enabled || !u.AllowsNode(nodeID) {
			continue
		}
		users = append(users, nodeUser{Name: u.Name, UUID: u.UUID})
	}
	// 排序后再算摘要：内核配置里的顺序才是稳定的，否则 Store 内部顺序抖动一下
	// 就会让 revision 变化、白白重载一次内核。
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })

	h := sha256.New()
	for _, u := range users {
		fmt.Fprintf(h, "%s\x00%s\x00", u.Name, u.UUID)
	}
	sum := h.Sum(nil)
	writeJSON(w, 200, map[string]any{
		"revision": fmt.Sprintf("%x", sum[:8]),
		"users":    users,
	})
}

// NodeHash 是一个账号在「哈希名单」里的最小表示。
//
// 导出是因为两台机器共用它：出口节点构造（见 handleNodeHashes），
// 落地节点解析（见 cmd/transrelay）。
type NodeHash struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

// handleNodeHashes 把「被授权使用这个节点」的账号的 bcrypt 哈希发给它。
//
// 【为什么单独一个接口，而不是并进 /node/users】
// /node/users 是渲染通道A（REALITY）用的，只需要 UUID。把哈希混在里面，
// 一个只跑通道A 的节点也会顺手拿到一批密码哈希。拆成两个接口之后，
// 「谁领过哈希」在代码里和日志里都是一处显式行为，而不是副产品。
//
// 【这个取舍必须写清楚】
// bcrypt 可以离线爆破：拿到哈希的机器被攻陷，等于这些账号的密码被人带走慢慢试，
// 而人往往在别处复用同一个密码。之所以还是接受，是因为「分支节点A借出口节点的证书
// 提供通道B」就必然要自己判断密码对不对 —— 而这一点无法在不把某种可校验材料
// 放到那台机器上的前提下做到（这也是用户明确选定的方案）。
//
// 仍然守住两条：只发**启用且被授权用这个节点**的账号；只走已认证的节点通道，
// 且哈希绝不进日志。
func (s *Service) handleNodeHashes(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.Header.Get("X-Node-Id"))
	if !s.Relays.Authenticate(nodeID, r.Header.Get("X-Node-Token")) {
		errJSON(w, 401, "节点认证失败")
		return
	}
	all := s.Store.List()
	out := make([]NodeHash, 0, len(all))
	for _, u := range all {
		if !u.Enabled || !u.AllowsNode(nodeID) || u.Password == "" {
			continue
		}
		out = append(out, NodeHash{Name: u.Name, Hash: u.Password})
	}
	// 排序让输出稳定：节点那边是整表替换，顺序固定便于比对与排查。
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	s.Log("节点 %s 领取了 %d 个账号的密码哈希（用于在本机校验通道B）", nodeID, len(out))
	writeJSON(w, 200, map[string]any{"users": out})
}

// ---------- 落地节点的流量与访问记录上报 ----------
//
// 落地节点（分支节点A）自己出网，总节点这边看不到它的字节，所以「每个账号用了多少」
// 「访问了哪些域名」只能由它统计后报过来。
//
// 【安全前提】这一路是**不可信输入**：
//   - 通道是 HTTPS + 正常校验证书（节点侧不做任何降级），认证是每节点一把的随机口令；
//   - 但即使这样，一个被攻陷的节点也能报出任意数字。所以下面三条都要做：
//     增量截断（防止把某账号的累计用量顶到天上）、访问行限量限长（防止撑爆日志）、
//     账号名必须存在于库里且被授权用这个节点（否则丢弃）。

const (
	// maxNodeReportBytes 单次上报里单个账号允许的最大增量。
	// 30 秒内单账号 100 GB 已远超真实可能，超过就按上限截断并记日志。
	maxNodeReportBytes = 100 << 30
	// maxNodeReportBody 是上报请求体的上限，防止有人往这个公网接口灌大包。
	maxNodeReportBody = 1 << 20
	// 单次上报最多接收的访问记录条数，以及单行的最大长度。
	maxAccessLinesPerReport = 2000
	maxAccessLineLen        = 2048
)

// NodeStat 是落地节点上报的「某账号自上次上报以来的字节增量」。
//
// 导出是因为两台机器共用它：总节点这边解析、分支节点A那边构造（见 cmd/transrelay）。
type NodeStat struct {
	Name string `json:"name"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

// handleNodeReport 接收落地节点上报的每用户流量与访问记录。
func (s *Service) handleNodeReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	nodeID := strings.TrimSpace(r.Header.Get("X-Node-Id"))
	if !s.Relays.Authenticate(nodeID, r.Header.Get("X-Node-Token")) {
		errJSON(w, 401, "节点认证失败")
		return
	}
	var req struct {
		Stats  []NodeStat `json:"stats"`
		Access []string   `json:"access"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNodeReportBody)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}

	applied, skipped := 0, 0
	for _, st := range req.Stats {
		name := strings.TrimSpace(st.Name)
		up, down := clampDelta(st.Up), clampDelta(st.Down)
		if name == "" || (up == 0 && down == 0) {
			continue
		}
		// 只认「存在、启用、且被授权用这个节点」的账号：被攻陷的节点不该能
		// 给别人的账号虚增用量，也不该给未授权的账号记账。
		u, ok := s.Store.Snapshot(name)
		if !ok || !u.Enabled || !u.AllowsNode(nodeID) {
			skipped++
			continue
		}
		if err := s.Store.Modify(name, func(u *User) { u.UsedBytes += up + down }); err != nil {
			skipped++
			continue
		}
		s.noteRemoteStat(name, up, down)
		applied++
	}

	lines := s.appendRemoteAccess(req.Access)
	if applied > 0 || lines > 0 || skipped > 0 {
		s.Log("落地节点 %s 上报：%d 个账号的流量、%d 条访问记录（忽略 %d 条无效账号）",
			nodeID, applied, lines, skipped)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// remoteRateTTL 是「落地节点报上来的速率」的有效期。
// 超过它没收到新上报就按 0 处理：节点掉线时不该继续显示旧速率。
const remoteRateTTL = 90 * time.Second

// noteRemoteStat 记下落地节点上报的增量对应的实时速率。
//
// 速率按两轮上报的间隔算。间隔异常（第一次上报、或节点卡了很久才报）时只更新累计、
// 不动速率 —— 否则会算出一个大得离谱的瞬时值。
func (s *Service) noteRemoteStat(name string, up, down int64) {
	now := time.Now()
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if !s.remoteAt.IsZero() {
		if d := now.Sub(s.remoteAt); d >= time.Second && d <= 5*time.Minute {
			sec := d.Seconds()
			s.remoteRate[name] = TrafficPair{
				Up:   int64(float64(up) / sec),
				Down: int64(float64(down) / sec),
			}
		}
	}
	s.remoteAt = now
}

// remoteRateFor 返回落地节点报上来的实时速率（字节/秒）。节点掉线后自动归零。
func (s *Service) remoteRateFor(name string) TrafficPair {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.remoteAt.IsZero() || time.Since(s.remoteAt) > remoteRateTTL {
		return TrafficPair{}
	}
	return s.remoteRate[name]
}

// clampDelta 把上报的增量夹到合理区间：负数与天文数字都当成不可信输入处理。
func clampDelta(v int64) int64 {
	if v <= 0 {
		return 0
	}
	if v > maxNodeReportBytes {
		return maxNodeReportBytes
	}
	return v
}

// appendRemoteAccess 把落地节点上报的访问记录追加到本机的内核访问日志。
//
// 追加而不是另存一份：监控采集器就是按偏移增量读这个文件的，写进去之后
// 「面板里的访问记录」不用改一行代码就能带上落地节点的数据。
func (s *Service) appendRemoteAccess(lines []string) int {
	if len(lines) == 0 {
		return 0
	}
	var b strings.Builder
	n := 0
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r\n")
		if ln == "" {
			continue
		}
		if len(ln) > maxAccessLineLen {
			ln = ln[:maxAccessLineLen]
		}
		b.WriteString(ln)
		b.WriteByte('\n')
		n++
		if n >= maxAccessLinesPerReport {
			break
		}
	}
	if n == 0 {
		return 0
	}
	f, err := os.OpenFile(XrayAccessLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		s.Log("写入落地节点访问记录失败: %v", err)
		return 0
	}
	defer f.Close()
	if _, err := f.WriteString(b.String()); err != nil {
		s.Log("写入落地节点访问记录失败: %v", err)
		return 0
	}
	return n
}
