package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HysteriaAvailable 判断本机是否装了 hysteria 可执行文件。
// 双通道是可选能力：没装时整套系统应当照常单通道运行，所以这里只检测，不强制依赖。
func HysteriaAvailable() bool {
	_, err := os.Stat("/usr/local/bin/hysteria")
	return err == nil
}

// HysteriaFile 是部署时写在数据目录里的双通道参数。
type HysteriaFile struct {
	Port        int    `json:"port"`
	Obfs        string `json:"obfs"`
	StatsSecret string `json:"statsSecret"`
	StatsListen string `json:"statsListen"`
}

// loadHysteriaFile 读取双通道参数。文件不存在即表示未部署 hysteria，
// 返回 false 让调用方按单通道处理——双通道是可选能力，不该成为启动前提。
func loadHysteriaFile(path string) (HysteriaFile, bool) {
	var h HysteriaFile
	b, err := os.ReadFile(path)
	if err != nil {
		return h, false
	}
	if json.Unmarshal(b, &h) != nil {
		return h, false
	}
	if h.StatsListen == "" {
		h.StatsListen = "127.0.0.1:9999"
	}
	return h, true
}

// QueryHysteriaTraffic 读取 hysteria 的按账号流量。
//
// 返回的是「自上次调用以来的增量」：带 clear=1 时服务端读完即清零，
// 所以拿到的是本次轮询区间内的字节数，不是累计值。
//
// 上下行分开返回而不是加总。管理面板要显示每人的实时上行/下行速率，
// 合并成一个数字之后就再也拆不开了；而 hysteria 本来就分了 tx/rx。
//
// 方向约定（依据 hysteria 的 server/copy.go）：Tx 是用户上行、Rx 是用户下行。
// 它的文档注释按「服务端→代理目标」的口径描述，容易读反；
// 以代码为准——client→target 那段被计到 Tx，target→client 那段被计到 Rx。
// 这与内核对 uplink/downlink 的口径（都是站在用户视角）一致。
func QueryHysteriaTraffic(listen, secret string, timeout time.Duration) (map[string]TrafficPair, error) {
	if secret == "" || listen == "" {
		return nil, nil
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+listen+"/traffic?clear=1", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", secret)
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hysteria 统计接口返回 %d", resp.StatusCode)
	}
	var raw map[string]struct {
		Tx int64 `json:"tx"`
		Rx int64 `json:"rx"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make(map[string]TrafficPair, len(raw))
	for name, v := range raw {
		if name == "" {
			continue
		}
		out[name] = TrafficPair{Up: v.Tx, Down: v.Rx}
	}
	return out, nil
}

// redactHysteriaAuth 把认证请求里的密码换成占位符，字段结构原样保留。
//
// 为什么要打这行日志：这类协议字段名一旦记错，唯一可靠的核对方式就是看真机请求。
// 但请求里的 auth 字段就是「账号:密码」——直接打原文等于把全站密码写进系统日志，
// 而日志会被长期留存、可能被采集、也会被多人查看。所以保留结构、隐去凭据。
//
// 解析不出来时整体隐去：宁可少记一行，也不冒险把可能是密码的内容写出去。
// 也不打密码长度——长度本身也是信息。
func redactHysteriaAuth(raw []byte) string {
	var v struct {
		Addr string `json:"addr"`
		Auth string `json:"auth"`
		Tx   int64  `json:"tx"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "<无法解析，已整体隐去>"
	}
	name, _, ok := strings.Cut(v.Auth, ":")
	if !ok {
		name = v.Auth
	}
	if name == "" {
		name = "<空>"
	}
	return fmt.Sprintf(`{"addr":%q,"auth":%q,"tx":%d}`, v.Addr, name+":<已隐去>", v.Tx)
}

// HysteriaAuth 是 hysteria2 HTTP 认证回调的共享实现。
//
// 【为什么要共用一份】
// 这个回调是「每建立一条连接就问一次」的，出口节点（总节点）与分支节点A上各有一份：
// 前者挂在控制面的 HTTPS 服务上（见 handleHysteriaAuth），后者由 cmd/transrelay
// 在本机回环上提供。两处各写一份判断的话，改了密码之后很容易变成
// 「通道A 失效了、通道B 还能用」—— 而这种不一致没有任何地方会报错。
//
// 【为什么走 HTTP 回调，而不是把账号写进 hysteria 配置】
// 账号库只有一份（bcrypt 哈希）。让内核每次连接都来问，就不会出现
// 「改了密码、但另一条通道里还留着一份旧的」这种状态。
type HysteriaAuth struct {
	// Lookup 按账号名返回 bcrypt 哈希。ok=false 表示账号不存在或不可用（停用等）。
	//
	// 返回哈希而不是直接返回布尔，是为了让「密码比对」也只有一处实现。
	Lookup func(name string) (hash string, ok bool)
	// Lim 是失败限速。为 nil 表示不限速 —— 不要这么用，理由见 Serve。
	Lim *FailLimiter
	// Log 记认证请求（密码会被隐去，见 redactHysteriaAuth）。
	Log func(format string, args ...any)
}

// Serve 处理一次认证请求，返回 HTTP 状态码与响应体。
//
// 协议：hysteria 服务端会 POST 一个 JSON 过来——
//
//	{"addr": "1.2.3.4:5678", "auth": "用户名:密码", "tx": <客户端已用流量字节>}
//
// 返回 200 表示放行，其它状态码一律拒绝。
//
// 限速是必需的，不是锦上添花：每收到一次失败的认证就要做一次 bcrypt 比较，
// 而 hysteria 的端口是对公网开放的 —— 不限速的话，任何人都能拿它当
// 「按用户名试密码」的免费算力，顺便把这台机器的 CPU 打满。
func (h HysteriaAuth) Serve(raw []byte) (int, map[string]any) {
	logf := h.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logf("hysteria 认证请求: %s", redactHysteriaAuth(raw))

	var req struct {
		Addr string `json:"addr"`
		Auth string `json:"auth"`
		Tx   int64  `json:"tx"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return http.StatusBadRequest, map[string]any{"error": "bad json"}
	}

	name, pass, ok := strings.Cut(req.Auth, ":")
	if !ok || name == "" || pass == "" {
		// 连账号名都拼不出来的请求不算一次「密码试错」，不记进限速表：
		// 否则随手发的空请求就能把限速表撑大（见 loginTrackMaxKeys）。
		return http.StatusUnauthorized, map[string]any{"error": "unauthorized"}
	}
	if h.Lim != nil {
		// 来源地址恒为本机（hysteria 就在同一台机器上），所以只按账号名计数。
		if d := h.Lim.Blocked(name, ""); d > 0 {
			return http.StatusTooManyRequests, map[string]any{"error": "too many attempts"}
		}
	}

	var hash string
	var found bool
	if h.Lookup != nil {
		hash, found = h.Lookup(name)
	}
	if !found || bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		if h.Lim != nil {
			h.Lim.Note(name, "", false)
		}
		// 账号不存在 / 已停用 / 密码不对：一律同一个状态码，避免被用来枚举账号。
		// 不存在的账号同样记一次失败，使「反复试不存在的账号」也会被限速。
		return http.StatusForbidden, map[string]any{"error": "forbidden"}
	}
	if h.Lim != nil {
		h.Lim.Note(name, "", true)
	}
	// id 会被 hysteria 当作流量统计的键。不返回它，所有用户会挤在空键上，
	// 就没法按账号算用量了；udp 置真才允许 UDP 中继。
	return http.StatusOK, map[string]any{"ok": true, "id": name, "udp": true}
}

// handleHysteriaAuth 是出口节点（总节点）上的回调入口。
//
// 它挂在控制面的 HTTPS 服务上，hysteria 的配置里写的是
// https://127.0.0.1:8443/api/v1/hysteria/auth。判断逻辑本身在 HysteriaAuth.Serve 里。
func (s *Service) handleHysteriaAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 只接受来自本机的调用：这个接口是给同一台机器上的 hysteria 进程用的。
	//
	// 如果它暴露在公网上，就等于开放了一个「不需要任何令牌、每次请求都能触发一次
	// bcrypt 比较」的密码校验接口——既能被拿来暴力破解，也能靠它把 CPU 打满。
	if !IsLoopback(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	code, resp := s.hysteriaAuth().Serve(raw)
	writeJSON(w, code, resp)
}

// hysteriaAuth 把账号库接进共享的认证实现。
//
// 每次都现取（而不是缓存一份）：账号可能刚被管理命令这个独立进程改动，
// 缓存会让「刚改的密码」在下一次重启之前一直不生效。
func (s *Service) hysteriaAuth() HysteriaAuth {
	return HysteriaAuth{
		Lookup: func(name string) (string, bool) {
			u, ok := s.Store.Snapshot(name)
			if !ok || !u.Enabled {
				return "", false
			}
			return u.Password, true
		},
		Lim: s.lim,
		Log: s.Log,
	}
}
