package ctl

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// 采集间隔决定「实时速率」的粒度：它算的是一段区间的平均值，
	// 所以间隔越长越迟钝。5 秒与客户端刷新周期一致，观感最接近实时。
	pollInterval = 5 * time.Second
	tokenTTL     = 7 * 24 * time.Hour

	// 登录/认证失败限速的参数。为什么两个维度都要看、阈值为什么差这么多，
	// 见 FailLimiter 的说明。
	loginWindow    = 10 * time.Minute
	loginMaxFail   = 10
	loginMaxIPFail = 30
	loginBlockTime = 10 * time.Minute
	// loginTrackMaxKeys 是限速表的键数上限。
	// 不设上限的话，攻击者用**随机用户名**刷 /login 就能把这张表无限撑大——
	// 每个不存在的账号都会留下一个条目，而这条路径几乎不耗 CPU，成本极低。
	loginTrackMaxKeys = 4096
)

// liveStat 是某个用户在当前这次内核运行周期内的实时数据，不落盘。
type liveStat struct {
	SessionUp   int64
	SessionDown int64
	UpSpeed     int64
	DownSpeed   int64
}

// Service 把账号库、内核参数与内核 API 粘合成对外服务。
type Service struct {
	Store    *Store
	Settings ServerSettings
	Log      func(format string, args ...any)

	liveMu   sync.RWMutex
	live     map[string]liveStat
	prev     map[string]TrafficPair
	lastPoll time.Time

	// hyTotal 累计通道B（hysteria）自本进程启动以来各账号的上下行字节数。
	//
	// hysteria 的统计接口是「读取即清零」的增量，本身只随连接生命周期存在，
	// 拿不到像内核那样的「开机以来累计值」；而面板要显示会话累计，
	// 所以在这里按进程生命周期累加。它与通道A 的计时起点不同
	// （内核是自内核启动，这里是自控制面启动），面板上标注为「本次运行」。
	hyTotal map[string]TrafficPair

	// baselineReady 为假表示这是本次服务启动后的第一次采集。
	// 第一次只建立基线、不记账，理由见 pollOnce 里的说明。
	baselineReady bool

	// AdminToken 是监控接口的凭据，与用户令牌完全分开，理由见 admin.go。
	AdminToken string
	// Relays 是中转节点登记表。为 nil 表示本次运行没启用中转（单线路部署）。见 nodes.go。
	Relays *RelayRegistry
	// remoteMu 保护下面两个字段：它们记的是**落地节点报上来的**实时速率。
	// 出口在那台机器上，本机内核看不到它的字节，所以速率只能由它报过来再叠加。
	remoteMu   sync.Mutex
	remoteRate map[string]TrafficPair
	remoteAt   time.Time
	// Mon 是访问记录采集器；为 nil 表示本次运行不采集（接口会返回空结果而不是报错）。
	Mon *Monitor

	// lim 是登录与认证失败的限速表。与 hysteria 的认证回调共用同一个实例：
	// 「密码试错」在这台机器上只有一本账，两条通道的失败次数互相累加。
	lim *FailLimiter
}

func NewService(st *Store, s ServerSettings, logf func(string, ...any)) *Service {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	svc := &Service{
		Store: st, Settings: s, Log: logf,
		live: map[string]liveStat{}, prev: map[string]TrafficPair{},
		hyTotal:    map[string]TrafficPair{},
		remoteRate: map[string]TrafficPair{},
		lim:        NewFailLimiter(logf),
	}
	// 登记表读不出来（比如格式被打坏）只记一行日志、按「没有中转」继续跑：
	// 中转是附加能力，不该因为它把主线服务一起拖起不来。
	if p := strings.TrimSpace(s.NodesPath); p != "" {
		reg, err := LoadRelayRegistry(p)
		if err != nil {
			logf("节点登记表加载失败，本次按单线路运行: %v", err)
		} else {
			svc.Relays = reg
		}
	}
	return svc
}

// ---------- 令牌 ----------
//
// 令牌载荷是「账号名|UUID|过期时间」，用账号库里的 Secret 做 HMAC。
//
// 为什么要把 UUID 放进去：UUID 是账号在内核里的身份，改密码时会被换成新的。
// 令牌里带上它，校验时与库里的当前值一比，**改密码就等于吊销该账号的全部旧令牌**。
// 否则会出现「用户发现令牌泄露后改了密码，但攻击者拿旧令牌仍能用满 7 天」——
// 改密码就失去了「夺回账号」的作用。

func (s *Service) signToken(name, uuid string, exp time.Time) string {
	payload := fmt.Sprintf("%s|%s|%d", name, uuid, exp.Unix())
	mac := hmac.New(sha256.New, []byte(s.Store.TokenSecret()))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyToken 校验签名与有效期，返回账号名。
func (s *Service) verifyToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("令牌格式错误")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("令牌无法解码")
	}
	mac := hmac.New(sha256.New, []byte(s.Store.TokenSecret()))
	mac.Write(raw)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(mac.Sum(nil), got) {
		return "", fmt.Errorf("令牌签名不匹配")
	}
	fields := strings.Split(string(raw), "|")
	if len(fields) != 3 {
		// 旧版令牌只有「账号名|过期时间」。签名是对整段载荷算的，
		// 所以这里会直接判为格式异常，客户端重新登录即可。
		return "", fmt.Errorf("令牌载荷异常")
	}
	exp, _ := strconv.ParseInt(fields[2], 10, 64)
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("登录已过期，请重新登录")
	}
	// 与库里当前的 UUID 比对，实现「改密码即吊销」。
	u, found := s.Store.Snapshot(fields[0])
	if !found || u.UUID != fields[1] {
		return "", fmt.Errorf("登录状态已失效，请重新登录")
	}
	return fields[0], nil
}

// authUser 校验请求里的令牌并取出对应账号，顺带确认账号仍可用。
//
// 各接口都要做这一串校验，集中在这里可以避免「某个接口忘了判断 Enabled」
// 这类不一致——历史上就出现过停用账号仍能查询流量的情况。
func (s *Service) authUser(r *http.Request) (*User, error) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return nil, fmt.Errorf("缺少授权令牌")
	}
	name, err := s.verifyToken(strings.TrimSpace(strings.TrimPrefix(h, p)))
	if err != nil {
		return nil, err
	}
	u, found := s.Store.Snapshot(name)
	if !found || !u.Enabled {
		return nil, fmt.Errorf("账号不可用")
	}
	return &u, nil
}

// clientIP 取请求来源 IP，仅用于限速。
//
// 刻意不看 X-Forwarded-For：那个头客户端可以随便伪造，拿它限速等于没有限速。
// 服务端是直接对外暴露的、前面没有反向代理，所以 RemoteAddr 就是真实来源。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IsLoopback 判断请求是不是来自本机。
//
// 导出是因为落地节点（分支节点A）上的 transrelay 也要做同一个判断（它在本机回环上
// 提供 hysteria 的认证回调）。这类「安全判断」只该有一份实现。
func IsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ---------- 登录失败限速 ----------
//
// 抽成独立类型是因为同一套判断有两个使用方：控制面的 /api/v1/login，
// 以及 hysteria 的认证回调。后者在出口节点（总节点）与落地节点（分支节点A）各起一份 ——
// 它们是两台机器、两套进程，各记各的账即可；但**判断规则必须是同一份代码**，
// 否则「一个账号在一条通道上被限速、在另一条上还能尽情试」这种不一致没人会发现。
//
// 为什么两个维度都要看：
//
//   - 只按账号名：攻击者知道用户名后，每 10 分钟制造 10 次失败就能把该用户锁死，
//     一个不需要任何成本的定向拒绝服务。
//   - 只按来源 IP：公网接口换个 IP 就绕过去了。
//
// 所以两条都记；账号名的阈值低（打的是爆破），IP 的阈值高得多（打的是撒网扫描，
// 又不能把同一个 NAT 出口后面的正常用户误伤）。
type FailLimiter struct {
	mu      sync.Mutex
	fails   map[string][]time.Time
	blocked map[string]time.Time
	log     func(string, ...any)
}

// NewFailLimiter 建一张限速表。logf 允许为 nil。
func NewFailLimiter(logf func(string, ...any)) *FailLimiter {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &FailLimiter{
		fails:   map[string][]time.Time{},
		blocked: map[string]time.Time{},
		log:     logf,
	}
}

// Blocked 返回该「账号名 + 来源 IP」组合的剩余封锁时长，0 表示没被封。
//
// ip 传空串即只按账号名统计。hysteria 的认证回调就是这么用的：请求恒来自本机，
// 按 IP 统计没有任何区分度，反而会把所有用户算成同一个来源。
func (l *FailLimiter) Blocked(name, ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return maxDuration(l.blockedForLocked("u:"+name), l.blockedForLocked("i:"+ip))
}

// Note 记一次认证结果。成功即清掉该账号的失败记录，避免「差点被锁死的账号
// 在成功登录之后仍然带着旧账」。
func (l *FailLimiter) Note(name, ip string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	uk := "u:" + name
	if ok {
		delete(l.fails, uk)
		delete(l.blocked, uk)
		return
	}
	now := time.Now()
	l.bumpLocked(uk, now, loginMaxFail, "账号")
	if ip != "" {
		l.bumpLocked("i:"+ip, now, loginMaxIPFail, "来源 IP")
	}
	// 限速表必须有上限，理由见 loginTrackMaxKeys。
	if len(l.fails) > loginTrackMaxKeys {
		l.sweepLocked(now)
	}
}

// blockedForLocked 返回该键的剩余封锁时长，过期即顺手清掉。
// 调用方必须已持有 l.mu。
func (l *FailLimiter) blockedForLocked(key string) time.Duration {
	until, ok := l.blocked[key]
	if !ok {
		return 0
	}
	if d := time.Until(until); d > 0 {
		return d
	}
	delete(l.blocked, key)
	return 0
}

// bumpLocked 记一次失败，达到阈值就封锁该键。调用方必须已持有 l.mu。
func (l *FailLimiter) bumpLocked(key string, now time.Time, limit int, label string) {
	cutoff := now.Add(-loginWindow)
	kept := make([]time.Time, 0, len(l.fails[key])+1)
	for _, t := range l.fails[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	l.fails[key] = kept
	if len(kept) >= limit {
		l.blocked[key] = now.Add(loginBlockTime)
		delete(l.fails, key)
		l.log("登录失败过多（按%s统计），已临时封锁 %s", label, loginBlockTime)
	}
}

// sweepLocked 清理限速表里过期的条目；清不掉就整表重置。
//
// 整表重置是刻意的兜底：限速短暂失效几秒，也比内存被随机用户名刷爆、
// 导致整个控制面（含流量采集与管理接口）不可用要好。
// 调用方必须已持有 l.mu。
func (l *FailLimiter) sweepLocked(now time.Time) {
	cutoff := now.Add(-loginWindow)
	for k, v := range l.fails {
		if len(v) == 0 || v[len(v)-1].Before(cutoff) {
			delete(l.fails, k)
		}
	}
	if len(l.fails) > loginTrackMaxKeys {
		l.log("登录失败记录表超过 %d 项，已重置（疑似被大量随机用户名刷接口）", loginTrackMaxKeys)
		l.fails = map[string][]time.Time{}
	}
}

// loginBlocked / noteLoginResult 是 Service 侧的薄封装，让处理器读起来短一些。
func (s *Service) loginBlocked(name, ip string) time.Duration { return s.lim.Blocked(name, ip) }
func (s *Service) noteLoginResult(name, ip string, ok bool)   { s.lim.Note(name, ip, ok) }

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// ---------- 路由 ----------

// Handler 返回全部对外接口。
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/login", s.handleLogin)
	mux.HandleFunc("/api/v1/profile", s.handleProfile)
	mux.HandleFunc("/api/v1/traffic", s.handleTraffic)
	mux.HandleFunc("/api/v1/password", s.handlePassword)
	// Hysteria2 的认证回调：由本机的 hysteria 进程调用，不经过用户浏览器。
	mux.HandleFunc("/api/v1/hysteria/auth", s.handleHysteriaAuth)

	// 落地节点用的接口。认证走「节点 id + 节点口令」，与用户令牌、管理员令牌都无关，理由见 nodes.go。
	mux.HandleFunc("/api/v1/node/register", s.handleNodeRegister)
	mux.HandleFunc("/api/v1/node/users", s.handleNodeUsers)
	// 通道B 的凭据。单独一个接口而不是并进 /node/users：只跑通道A 的节点不该拿到哈希。
	mux.HandleFunc("/api/v1/node/hashes", s.handleNodeHashes)
	// 落地节点上报每用户流量与访问记录（它自己出网，本机看不到那些字节）。
	mux.HandleFunc("/api/v1/node/report", s.handleNodeReport)

	// 监控接口。单独一段命名空间、单独的令牌，理由见 admin.go。
	mux.HandleFunc("/api/v1/admin/overview", s.handleAdminOverview)
	mux.HandleFunc("/api/v1/admin/events", s.handleAdminEvents)
	mux.HandleFunc("/api/v1/admin/top", s.handleAdminTop)
	// 账号管理（增删改）。同样只认管理员令牌。
	mux.HandleFunc("/api/v1/admin/user/create", s.handleAdminUserCreate)
	mux.HandleFunc("/api/v1/admin/user/update", s.handleAdminUserUpdate)
	mux.HandleFunc("/api/v1/admin/user/delete", s.handleAdminUserDelete)

	// 下载页。刻意只注册这个深层前缀：根路径不注册任何东西，
	// 所以访问 / 只会得到 404，不给扫描器留下「这里有个站」的印象。
	if p := s.downloadPrefix(); p != "" {
		mux.HandleFunc(p+"/", s.handleDownload)
	}
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

// handleHealth 是唯一不需要鉴权的接口，客户端用它做「服务是否活着」的预检。
//
// 刻意**不返回** REALITY 的 publicKey / shortId / SNI：这些是连接参数，
// 公开出去等于给扫描器提供了「确认这台机器就是某个 REALITY 节点」的依据，
// 而客户端本来就能从登录响应里拿到它们，这里没有必须公开的理由。
// 管理工具需要这些参数时走本机的 transctl showparams，不依赖这个公网接口。
func (s *Service) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok": true, "service": "transctl", "serverTime": time.Now().Unix(),
		// 混不混淆口令都是凭据，只在通过鉴权的 /login 响应里下发。
		"hysteriaEnabled": s.Settings.HysteriaEnabled,
	})
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// dummyHash 用于「账号不存在」时付一次等价代价的哈希比较。
//
// 不这么做的话，登录接口对不存在的账号会直接短路返回，耗时明显短于「密码错误」
// （后者要跑一次 bcrypt）。即便两边的返回文案完全一样，攻击者用响应耗时就能
// 把有效账号名枚举出来——正好绕过了旁边「不区分账号与密码错误」的用意。
// 内容是启动时随机生成的，不参与任何认证。
var dummyHash = func() []byte {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil
	}
	h, err := bcrypt.GenerateFromPassword(buf, bcrypt.DefaultCost)
	if err != nil {
		return nil
	}
	return h
}()

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	var req loginReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	ip := clientIP(r)

	if d := s.loginBlocked(req.Username, ip); d > 0 {
		errJSON(w, 429, fmt.Sprintf("登录失败次数过多，请 %d 分钟后再试", int(d.Minutes())+1))
		return
	}

	u, found := s.Store.Snapshot(req.Username)
	if !found && len(dummyHash) > 0 {
		// 不存在的账号也要付一次同样代价的比较，理由见 dummyHash。
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
	}
	if !found || !u.Enabled || !u.CheckPassword(req.Password) {
		s.noteLoginResult(req.Username, ip, false)
		// 不区分「账号不存在」与「密码错误」，避免被用来枚举有效账号。
		errJSON(w, 401, "账号或密码错误")
		return
	}
	s.noteLoginResult(req.Username, ip, true)

	params, err := s.Settings.ClientParams()
	if err != nil {
		errJSON(w, 500, "服务端配置异常: "+err.Error())
		return
	}
	exp := time.Now().Add(tokenTTL)
	writeJSON(w, 200, map[string]any{
		"username": u.Name,
		"note":     u.Note,
		"token":    s.signToken(u.Name, u.UUID, exp),
		"expireAt": exp.Unix(),
		// UUID 是该账号在内核里的身份，等价于连接凭据，只回给通过认证的本人。
		// 客户端拿它来建立隧道；改密码时它会一起更换，使旧参数立即失效。
		"uuid":   u.UUID,
		"params": params,
		// 可选线路表。客户端只认其中的参数、不认任何节点信息，所以加线路、
		// 改线路显示名都不用重发客户端。第一项即默认线路，中转线路按授权过滤。
		"instances": s.instancesOrNil(&u),
	})
}

// instancesOrNil 组装线路表，失败时返回 nil。
//
// 线路表不是连接的必需条件（客户端会退回用顶层 params），所以组装失败时只记一行
// 日志、不要因此让整个登录失败 —— 那会让所有人突然都连不上。
func (s *Service) instancesOrNil(u *User) []NodeInstance {
	list, err := s.Instances(u.AllowNodes)
	if err != nil {
		s.Log("组装线路表失败，本次只下发默认线路: %v", err)
		return nil
	}
	return list
}

func (s *Service) handleProfile(w http.ResponseWriter, r *http.Request) {
	u, err := s.authUser(r)
	if err != nil {
		errJSON(w, 401, err.Error())
		return
	}
	params, err := s.Settings.ClientParams()
	if err != nil {
		errJSON(w, 500, "服务端配置异常")
		return
	}
	writeJSON(w, 200, map[string]any{
		"username": u.Name, "note": u.Note, "uuid": u.UUID, "params": params,
		"instances": s.instancesOrNil(u),
	})
}

func (s *Service) handleTraffic(w http.ResponseWriter, r *http.Request) {
	u, err := s.authUser(r)
	if err != nil {
		errJSON(w, 401, err.Error())
		return
	}
	name := u.Name

	s.liveMu.RLock()
	l := s.live[name]
	collected := s.lastPoll.Unix()
	s.liveMu.RUnlock()

	writeJSON(w, 200, map[string]any{
		"username":       u.Name,
		"usedBytes":      u.UsedBytes,
		"quotaBytes":     u.QuotaBytes,
		"remainingBytes": u.Remaining(),
		"sessionUp":      l.SessionUp,
		"sessionDown":    l.SessionDown,
		"upSpeed":        l.UpSpeed,
		"downSpeed":      l.DownSpeed,
		// 用「最近活动时间」代替不可用的在线数，见 store.go 中 LastActive 的说明。
		"lastActive":  u.LastActive.Unix(),
		"collectedAt": collected,
	})
}

type passwordReq struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (s *Service) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	u, err := s.authUser(r)
	if err != nil {
		errJSON(w, 401, err.Error())
		return
	}
	name := u.Name
	var req passwordReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}
	if !u.CheckPassword(req.OldPassword) {
		errJSON(w, 400, "原密码不正确")
		return
	}
	if err := s.Store.SetPassword(name, req.NewPassword); err != nil {
		errJSON(w, 400, err.Error())
		return
	}

	// 改密会更换 UUID，因此同时产生两个效果：
	//   1. 已签发的旧令牌全部失效（令牌载荷里带着 UUID），账号被真正「夺回」；
	//   2. 内核里的旧身份失效，旧连接参数立刻不能再用。
	// 第 1 点是刻意设计，见 signToken 的说明；第 2 点要靠下面这次同步完成。
	if nu, ok := s.Store.Snapshot(name); ok {
		if err := s.ApplyUser(&nu); err != nil {
			s.Log("改密后同步内核用户失败: %v", err)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "密码已修改，旧连接参数已失效"})
}

// ---------- 内核同步 ----------

// syncConfigFile 把当前账号列表渲染写入内核配置文件。
// 运行中的变更靠 ApplyUser/DropUser 即时生效，写文件是为了内核重启后仍是新状态。
func (s *Service) syncConfigFile() error {
	b, err := RenderXrayConfig(s.Settings, s.Store.List())
	if err != nil {
		return err
	}
	tmp := CfgTempPath(XrayCfgPath)
	// 这份配置里有**全部账号的 UUID**（等价于连接凭据）与 REALITY 私钥，
	// 不能让其他本地用户读到。但内核以 nobody 运行，0600 它又读不到。
	// 所以用 root:<内核用户的组> + 0640：只有 root 能改、内核能读、其他人看不到。
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if gid := XrayRunGID(); gid >= 0 {
		if err := os.Chown(tmp, 0, gid); err != nil {
			s.Log("设置内核配置文件属组失败（文件将只有 root 可读，可能导致内核读不到）: %v", err)
		}
	} else {
		// 拿不到内核用户的组时退回 0644：宁可留一个已知的权限问题，
		// 也不要让内核读不到配置而整体不可用。
		s.Log("未能确定内核运行用户的组，内核配置将保持可被本地其他用户读取")
		if err := os.Chmod(tmp, 0o644); err != nil {
			return err
		}
	}
	return os.Rename(tmp, XrayCfgPath)
}

// ApplyUser 让某个账号的新身份立即在运行中的内核生效，并同步配置文件。
func (s *Service) ApplyUser(u *User) error {
	if err := RemoveUserRuntime(s.Settings.APIPort, u.Name, 5*time.Second); err != nil {
		// 首次添加时用户本来就不存在，这里不作为失败处理。
		s.Log("移除旧身份（可忽略）: %v", err)
	}
	if err := AddUserRuntime(s.Settings.APIPort, s.Settings, *u, 5*time.Second); err != nil {
		return err
	}
	return s.syncConfigFile()
}

// DropUser 让某个账号立即在内核里失效，并同步配置文件。
func (s *Service) DropUser(name string) error {
	if err := RemoveUserRuntime(s.Settings.APIPort, name, 5*time.Second); err != nil {
		s.Log("移除用户: %v", err)
	}
	return s.syncConfigFile()
}

// ---------- 流量采集 ----------

// StartPoller 周期性采集内核流量并累加到账号的持久化用量里。
func (s *Service) StartPoller(stop <-chan struct{}) {
	go func() {
		s.pollOnce()
		t := time.NewTicker(pollInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.pollOnce()
			}
		}
	}()
}

func (s *Service) pollOnce() {
	counters, err := QueryTraffic(s.Settings.APIPort, 5*time.Second)
	if err != nil {
		s.Log("采集流量失败: %v", err)
		return
	}
	now := time.Now()
	elapsed := pollInterval.Seconds()
	if !s.lastPoll.IsZero() {
		if d := now.Sub(s.lastPoll).Seconds(); d > 1 {
			elapsed = d
		}
	}

	s.liveMu.Lock()
	prev := s.prev
	s.lastPoll = now
	s.liveMu.Unlock()

	newLive := make(map[string]liveStat, len(counters))
	newPrev := make(map[string]TrafficPair, len(counters))
	deltas := make(map[string]int64, len(counters))

	for name, cur := range counters {
		p := prev[name]
		du, dd := cur.Up-p.Up, cur.Down-p.Down
		// 内核重启后计数器归零，此时把当前值整体当作增量，避免出现负增长。
		if du < 0 {
			du = cur.Up
		}
		if dd < 0 {
			dd = cur.Down
		}
		if !s.baselineReady {
			// 本次服务启动后的第一次采集只建立基线，不记账。
			//
			// 内核的计数器是「自内核启动以来」累计的，而基线只存在内存里：
			// 控制面一重启基线就没了，此时若把当前值当成增量，会把该账号
			// 的全部历史用量重新计一遍——实测重启一次就凭空多出十几个 GB。
			//
			// 代价是「控制面停止期间」的用量会漏计。控制面重启通常只有几秒，
			// 而重复计入是永久性的账目错误，两害相权取轻。
			du, dd = 0, 0
		}
		deltas[name] = du + dd
		newPrev[name] = cur
		newLive[name] = liveStat{
			SessionUp: cur.Up, SessionDown: cur.Down,
			UpSpeed:   int64(float64(du) / elapsed),
			DownSpeed: int64(float64(dd) / elapsed),
		}
	}
	// 基线建立完成，后续采集才做差分。
	s.baselineReady = true

	// 合并通道B（hysteria）：两条通道要算到同一份账上，
	// 否则用户走 hysteria 时面板里既看不到用量、实时速率也恒为 0。
	var hyTotal map[string]TrafficPair
	if s.Settings.HysteriaEnabled {
		hd, herr := QueryHysteriaTraffic(s.Settings.HysteriaStatsListen, s.Settings.HysteriaStatsSecret, 5*time.Second)
		if herr != nil {
			s.Log("采集 hysteria 流量失败: %v", herr)
		}

		// 在锁内只做纯计算：先把已有的累计值拷出来，累加完再整体换回去。
		// （hysteria 的接口是读后清零的，这里拿到的 d 就是本次区间的增量。）
		s.liveMu.Lock()
		hyTotal = make(map[string]TrafficPair, len(s.hyTotal)+len(hd))
		for k, v := range s.hyTotal {
			hyTotal[k] = v
		}
		s.liveMu.Unlock()
		for name, d := range hd {
			if name == "" {
				continue
			}
			acc := hyTotal[name]
			acc.Up += d.Up
			acc.Down += d.Down
			hyTotal[name] = acc
		}

		for name, d := range hd {
			if name == "" {
				continue
			}
			deltas[name] += d.Up + d.Down

			// 速率与内核那半边相加，而不是覆盖：用户可能同时开着两条通道。
			ls := newLive[name]
			ls.UpSpeed += int64(float64(d.Up) / elapsed)
			ls.DownSpeed += int64(float64(d.Down) / elapsed)
			// 会话累计按「自控制面启动以来」累加，与内核的「自内核启动以来」口径不同，
			// 面板上标注为「本次运行」。
			if t, ok := hyTotal[name]; ok {
				ls.SessionUp += t.Up
				ls.SessionDown += t.Down
			}
			newLive[name] = ls
		}
	}

	if err := s.Store.Update(func(u *User) bool {
		d, ok := deltas[u.Name]
		if !ok || d == 0 {
			return false
		}
		u.UsedBytes += d
		u.LastActive = time.Now()
		return true
	}); err != nil {
		s.Log("回写用量失败: %v", err)
	}

	s.liveMu.Lock()
	s.prev = newPrev
	s.live = newLive
	if hyTotal != nil {
		s.hyTotal = hyTotal
	}
	s.liveMu.Unlock()
}
