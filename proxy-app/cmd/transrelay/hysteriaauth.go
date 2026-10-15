package main

// 落地节点上的 hysteria2 认证回调。
//
// hysteria 的配置里 auth.type=http 指向 http://127.0.0.1:<port>/api/v1/hysteria/auth
// （见 ctl.RenderHysteriaConfig），请求由本文件处理。
//
// 【哈希只在本进程的内存里】
// 不落盘、不进配置文件、不进日志。于是「备份/拷贝一份 hysteria 配置」不会顺手
// 带走全站的密码哈希 —— 这是选择回调而不是 userpass 的主要理由。
//
// 【判断逻辑与出口节点共用】
// 真正的校验在 ctl.HysteriaAuth 里，出口节点用的是同一个实现。两处各写一份的话，
// 「改了密码、一条通道失效另一条还能用」这种不一致没有任何地方会报错。

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"transproxy/internal/ctl"
)

// hysteriaAuthReadLimit 与出口节点那份保持一致：认证请求体只有几十字节，
// 给到 8KB 已经非常宽松。
const hysteriaAuthReadLimit = 8192

type hysteriaAuth struct {
	mu    sync.RWMutex
	users map[string]string // 账号名 -> bcrypt 哈希
	auth  ctl.HysteriaAuth
	logf  func(string, ...any)
}

func newHysteriaAuth(logf func(string, ...any)) *hysteriaAuth {
	h := &hysteriaAuth{users: map[string]string{}, logf: logf}
	h.auth = ctl.HysteriaAuth{
		// 限速表独立于出口节点那份：这是另一台机器、另一个进程，
		// 而「密码试错」本来就该按机器分别计数。
		Lookup: h.lookup,
		Lim:    ctl.NewFailLimiter(logf),
		Log:    logf,
	}
	return h
}

func (h *hysteriaAuth) lookup(name string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hash, ok := h.users[name]
	return hash, ok
}

// setUsers 整体替换名单。
//
// 调用方在「拉不到最新名单」时**不应该**调它：一次网络抖动就把名单清空，
// 等于把所有通道B 用户挡在门外；沿用上一份名单只是「撤销授权晚生效一轮」。
func (h *hysteriaAuth) setUsers(users []ctl.NodeHash) {
	m := make(map[string]string, len(users))
	for _, u := range users {
		if u.Name != "" && u.Hash != "" {
			m[u.Name] = u.Hash
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users = m
}

func (h *hysteriaAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 兜一层：监听地址本来就配成 127.0.0.1，但万一被改成 0.0.0.0，
	// 这里也不至于让本机暴露一个「无需令牌、每次请求触发一次 bcrypt 比较」的接口。
	if !ctl.IsLoopback(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, hysteriaAuthReadLimit))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	code, resp := h.auth.Serve(raw)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

// serve 在回环上起监听，阻塞运行。
//
// 只返回监听失败（端口被占等）那一类错误。这里的取舍是：认证服务起不来只影响
// 通道B，通道A 与上报都还正常，所以调用方记一行日志就够，不该让整个进程退出。
func (h *hysteriaAuth) serve(listen string) error {
	mux := http.NewServeMux()
	mux.Handle(ctl.HysteriaAuthPath, h)
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// checkLoopbackListen 拦住「把认证监听配成对外地址」这种配置错误。
//
// 不拦的话，症状是「通道B 能用」，但那台机器上多了一个对公网的
// 口令校验接口，而没有任何迹象提示运维。所以在启动时就拒绝。
func checkLoopbackListen(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return &listenAddrError{listen}
	}
	return nil
}

type listenAddrError struct{ addr string }

func (e *listenAddrError) Error() string {
	return "认证回调只能监听回环地址，当前配置是 " + e.addr +
		"（它只由本机 hysteria 调用，暴露到公网等于开放一个免令牌的口令校验接口）"
}
