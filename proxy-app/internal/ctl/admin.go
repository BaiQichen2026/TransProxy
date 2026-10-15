package ctl

import (
	"crypto/subtle"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 监控接口（管理员专用）。
//
// 与 /api/v1 下的用户接口刻意分成两套凭据：
//   - 用户令牌（signToken）只能读自己的流量，是给客户端用的；
//   - 管理员令牌能读**所有人**的访问记录，是给监控端用的。
//
// 混用会导致一个很糟的后果：客户端一被逆向，全站所有人的浏览记录就都泄了。
// 两者分开之后，管理员令牌只存在于服务端与监控端，不下发到任何客户端。
const AdminTokenFile = "admin-token"

// LoadAdminToken 读取管理员令牌，不存在时生成一个。
//
// 令牌落盘而不是写死在配置里，是为了能随时轮换：删掉文件重启即可换新。
func LoadAdminToken(dataDir string) (string, error) {
	path := filepath.Join(dataDir, AdminTokenFile)
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	t := randomHex(32)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

// adminOK 校验管理员令牌。
// 用常数时间比较，避免按字节比较带来的时序侧信道。
func (s *Service) adminOK(r *http.Request) bool {
	if s.AdminToken == "" {
		return false
	}
	tok := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	if tok == "" {
		const p = "Bearer "
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, p) {
			tok = strings.TrimSpace(strings.TrimPrefix(h, p))
		}
	}
	if tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.AdminToken)) == 1
}

func (s *Service) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.adminOK(r) {
		// 不区分「没带令牌」与「令牌不对」，也不提示正确的头名称之外的信息。
		errJSON(w, 401, "管理员令牌无效")
		return false
	}
	return true
}

// handleAdminOverview 返回账号清单与采集状态，供监控页首屏使用。
func (s *Service) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	type userOut struct {
		Name       string `json:"name"`
		Enabled    bool   `json:"enabled"`
		Note       string `json:"note,omitempty"`
		UsedBytes  int64  `json:"usedBytes"`
		QuotaBytes int64  `json:"quotaBytes"`
		LastActive int64  `json:"lastActive"`

		// 实时速率，字节/秒。由控制面每 5 秒从内核与 hysteria 各采一次算出来，
		// 监控页据此显示「此刻谁在上传/下载」。
		// 两条通道的数值是相加的：用户可能同时开着 A、B 两条。
		UpSpeed   int64 `json:"upSpeed"`
		DownSpeed int64 `json:"downSpeed"`
		// 本次运行内的会话累计字节数（控制面重启后归零）。
		SessionUp   int64 `json:"sessionUp"`
		SessionDown int64 `json:"sessionDown"`

		// AllowNodes 是该账号被授权使用的中转线路 id 列表。
		// 面板据此显示「谁能用哪条线路」，也据此回填编辑表单。
		AllowNodes []string `json:"allowNodes"`
	}

	// 已登记的中转线路，供面板渲染授权选项。
	// 用 id + 显示名：授权用的是 id（要跟节点登记表对上），给人看的是显示名。
	type nodeOut struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Ready   bool   `json:"ready"`
		Granted int    `json:"granted"`
	}
	nodes := []nodeOut{}
	for _, n := range s.Relays.Snapshot() {
		granted := 0
		for _, u := range s.Store.List() {
			if u.AllowsNode(n.ID) {
				granted++
			}
		}
		nodes = append(nodes, nodeOut{ID: n.ID, Name: n.Name, Ready: n.Ready(), Granted: granted})
	}

	s.liveMu.RLock()
	live := make(map[string]liveStat, len(s.live))
	for k, v := range s.live {
		live[k] = v
	}
	speedAt := s.lastPoll.UnixMicro()
	s.liveMu.RUnlock()

	users := s.Store.List()
	out := make([]userOut, 0, len(users))
	for _, u := range users {
		var last int64
		if !u.LastActive.IsZero() {
			last = u.LastActive.UnixMicro()
		}
		l := live[u.Name]
		// 落地节点（分支节点A）报上来的速率叠加在这里：出口在那台机器上，
		// 本机内核看不到它的字节。节点掉线时 remoteRateFor 会自动归零。
		rem := s.remoteRateFor(u.Name)
		out = append(out, userOut{
			Name: u.Name, Enabled: u.Enabled, Note: u.Note,
			UsedBytes: u.UsedBytes, QuotaBytes: u.QuotaBytes, LastActive: last,
			UpSpeed: l.UpSpeed + rem.Up, DownSpeed: l.DownSpeed + rem.Down,
			SessionUp: l.SessionUp, SessionDown: l.SessionDown,
			// 保证是 [] 而不是 null：面板直接对它做 .includes()，null 会报错。
			AllowNodes: append([]string{}, u.AllowNodes...),
		})
	}

	// 监控接口里的所有时间统一为 Unix 微秒，与访问记录保持一致。
	// 注意这与客户端接口不同：/api/v1/traffic 的 lastActive 按秒，
	// 那是已发出去的客户端在用的格式，不能改。
	body := map[string]any{
		"serverTime": time.Now().UnixMicro(),
		"domain":     s.Settings.Domain,
		"users":      out,
		// 中转线路（含每条的授权人数），面板用它渲染授权勾选项。
		"relayNodes":    nodes,
		"localNodeId":   s.localNodeID(),
		"localNodeName": s.localNodeName(),
		"retainDays":    accessRetainDays,
		"hysteriaOn":    s.Settings.HysteriaEnabled,
		"collectorOn":   s.Mon != nil,
		"accessLatest":  s.accessLatest(),
		// 速率的采样时刻，供监控端判断这组数字有多新。
		"speedAt": speedAt,
	}
	if s.Mon != nil {
		ing, fail := s.Mon.Stats()
		body["ingested"] = ing
		body["parseFailed"] = fail
	}
	writeJSON(w, 200, body)
}

// accessLatest 返回内存里最新一条记录的时间，供监控端判断是否还有新数据。
func (s *Service) accessLatest() int64 {
	if s.Mon == nil {
		return 0
	}
	rec := s.Mon.Recent(1)
	if len(rec) == 0 {
		return 0
	}
	return rec[0].Time
}

// handleAdminEvents 按时间增量返回访问记录。
//
// 增量语义：返回 t >= since 的记录，最多 limit 条（取最新的那批）。
// since 与记录时间同为 Unix 微秒；监控端应当用「上一次拿到的最大 t」作为下次的 since。
// 另有 latest 字段可直接拿来当游标，省得自己从记录里取最大值。
func (s *Service) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.Mon == nil {
		writeJSON(w, 200, map[string]any{"events": []AccessRecord{}, "latest": 0})
		return
	}
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))

	recs, err := s.Mon.Query(since, strings.TrimSpace(q.Get("user")), strings.TrimSpace(q.Get("host")), limit)
	if err != nil {
		errJSON(w, 500, "读取访问记录失败: "+err.Error())
		return
	}
	var latest int64
	if len(recs) > 0 {
		latest = recs[len(recs)-1].Time
	}
	writeJSON(w, 200, map[string]any{"events": recs, "latest": latest})
}

// handleAdminTop 返回时间窗内的访问分布：域名 TopN + 每个账号的访问条数。
func (s *Service) handleAdminTop(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > accessRetainDays {
		days = 1
	}
	top, _ := strconv.Atoi(q.Get("limit"))
	if top <= 0 || top > 500 {
		top = 50
	}
	if s.Mon == nil {
		writeJSON(w, 200, map[string]any{"hosts": []HostCount{}, "byUser": map[string]int64{}, "total": 0})
		return
	}
	since := time.Now().AddDate(0, 0, -days).UnixMicro()
	hosts, byUser, total, err := s.Mon.Aggregate(since, strings.TrimSpace(q.Get("user")), top)
	if err != nil {
		errJSON(w, 500, "统计访问记录失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"hosts": hosts, "byUser": byUser, "total": total, "days": days,
	})
}
