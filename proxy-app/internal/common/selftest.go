package common

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SelfTest 无人值守验证整条链路：
// 启动内核 → 经本地代理请求境外站点 → 确认出口 IP → 确认国内站点直连 → 核对分流决策 → 系统代理读写与还原 → 清理。
func SelfTest(workDir string, p Profile, expectEgress string) (string, bool) {
	var sb strings.Builder
	pass := true
	check := func(name string, ok bool, detail string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			pass = false
		}
		fmt.Fprintf(&sb, "[%s] %s%s\n", status, name, detail)
	}

	// TUN 模式的系统侧参数必须先备好：物理网卡地址要在接管路由之前读取，
	// 而且它要写进配置（direct 出站绑定它），所以必须早于配置生成。
	var setup *TunSetup
	if p.TunMode {
		s, err := NewTunSetup(p.ServerAddr)
		if err != nil {
			check("准备 TUN 系统配置", false, " -> "+err.Error())
			return sb.String(), false
		}
		p.SendThrough = s.PhysIP
		setup = s
		defer func() {
			if setup != nil {
				setup.Cleanup()
			}
		}()
	}

	// 必须用 info 级别，才能从日志里看到每条连接命中的出站，用于核对分流。
	cfg := strings.Replace(ClientConfig(p), `"loglevel": "warning"`, `"loglevel": "info"`, 1)

	tun, err := Start(workDir, cfg)
	if err != nil {
		check("启动内核", false, " -> "+err.Error())
		return sb.String(), false
	}
	defer tun.Stop()

	// 先确认内核活着，再探端口。
	// 少了这步会出现很隐蔽的假成功：上次异常退出残留的内核仍占着端口，
	// 新内核绑定失败退出，而端口探测却「成功」——应答的是那个旧进程，
	// 于是所有后续断言都在测一个早已失效的配置。
	time.Sleep(time.Second)
	if !tun.Alive() {
		check("内核启动", false, " -> "+LastErrorLine(tun.LogText(4000)))
		return sb.String(), false
	}
	if !WaitPort(p.HTTPPort, 20*time.Second) {
		check("本地代理端口就绪", false, fmt.Sprintf(" -> 127.0.0.1:%d 未监听", p.HTTPPort))
		fmt.Fprintf(&sb, "内核日志:\n%s\n", tun.LogText(4000))
		return sb.String(), false
	}
	check("本地代理端口就绪", true, fmt.Sprintf(" -> 127.0.0.1:%d", p.HTTPPort))

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.HTTPPort))
	client := &http.Client{
		Timeout:   25 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	got := strings.TrimSpace(fetchBody(client, "https://api.ipify.org"))
	check("境外流量经代理出口", got == expectEgress,
		fmt.Sprintf(" -> api.ipify.org 返回 %q，期望 %q", got, expectEgress))

	code := fetchStatus(client, "https://www.google.com/generate_204")
	check("境外受限站点可达", code == "204", " -> google generate_204 返回 "+code)

	code = fetchStatus(client, "https://www.baidu.com")
	check("国内站点可达", code == "200" || code == "302", " -> baidu 返回 "+code)

	log := tun.LogText(400000)
	proxyLine := acceptedRoute(log, "api.ipify.org")
	directLine := acceptedRoute(log, "www.baidu.com")
	check("分流：境外命中 proxy", strings.Contains(proxyLine, "proxy"), "")
	check("分流：国内命中 direct", strings.Contains(directLine, "direct"), "")
	fmt.Fprintf(&sb, "  路由记录:\n    %s\n    %s\n", proxyLine, directLine)

	if p.TunMode {
		// TUN 模式要换一种验证思路：这里刻意「不设置任何代理」。
		// 如果请求依然从服务器出口出去，就说明流量确实被虚拟网卡整体接管了；
		// 用代理模式的思路去测，根本区分不出「TUN 生效」和「只是代理生效」。
		fmt.Fprintf(&sb, "=== TUN 模式补充验证 ===\n")
		time.Sleep(2 * time.Second)
		check("TUN 内核存活（虚拟网卡驱动已加载）", tun.Alive(), "")
		if !tun.Alive() {
			fmt.Fprintf(&sb, "内核日志:\n%s\n", tun.LogText(4000))
			return sb.String(), false
		}
		// 系统侧配置在这里应用。参数已在函数开头备好（必须在接管路由前读网关），
		// 这里只负责落地，保证自检走的是和客户端完全一致的路径。
		if err := setup.Apply(); err != nil {
			check("应用 TUN 系统配置", false, " -> "+err.Error())
			setup.Cleanup()
			return sb.String(), false
		}
		defer setup.Cleanup()
		check("TUN 系统配置已应用", true, " -> "+setup.Describe())
		// 不带任何 Proxy 字段的裸客户端。
		raw := &http.Client{Timeout: 30 * time.Second}
		gotRaw := strings.TrimSpace(fetchBody(raw, "https://api.ipify.org"))
		check("未配置任何代理，流量仍从服务器出口（TUN 已整体接管）", gotRaw == expectEgress,
			fmt.Sprintf(" -> api.ipify.org 返回 %q，期望 %q", gotRaw, expectEgress))
		codeRaw := fetchStatus(raw, "https://www.baidu.com")
		check("国内站点在 TUN 下仍直连可达", codeRaw == "200" || codeRaw == "302", " -> baidu 返回 "+codeRaw)
	}

	// 系统代理：改动前先快照，验证后精确还原。
	snap := SnapshotProxy()
	want := fmt.Sprintf("127.0.0.1:%d", p.HTTPPort)
	if err := EnableSystemProxy(p.HTTPPort); err != nil {
		check("开启系统代理", false, " -> "+err.Error())
	} else {
		on := normalizeDword(regQueryValue("ProxyEnable")) == "1"
		check("开启系统代理", on && CurrentProxy() == want,
			fmt.Sprintf(" -> enable=%v server=%s", on, CurrentProxy()))
	}
	if err := DisableSystemProxy(); err != nil {
		check("关闭系统代理", false, " -> "+err.Error())
	} else {
		off := normalizeDword(regQueryValue("ProxyEnable")) == "0"
		check("关闭系统代理", off, "")
	}
	RestoreProxy(snap)
	restored := "0"
	if snap.Enable != "" {
		restored = normalizeDword(snap.Enable)
	}
	check("还原系统代理", normalizeDword(regQueryValue("ProxyEnable")) == restored,
		" -> 已还原为改动前状态")

	return sb.String(), pass
}

// SelfTestChannel 在 SelfTest 的基础上支持第二条通道。
//
// 两条通道的校验内容完全一致（出口 IP、境外可达、国内直连、分流命中），
// 唯一差别是 Hysteria2 需要先把旁挂进程拉起来并等它的 SOCKS 端口就绪，
// 之后 xray 会把 proxy 出站指向那个端口，走的还是同一套分流逻辑。
func SelfTestChannel(workDir string, p Profile, username, pass, expectEgress string) (string, bool) {
	if p.Protocol == ProtoHysteria {
		if !p.HysteriaAvailable() {
			return "[FAIL] 服务端未下发 Hysteria2 通道参数，无法自检通道B\n", false
		}
		h, err := StartHysteria(workDir, HysteriaConfig(p, username, pass))
		if err != nil {
			return "[FAIL] 启动 Hysteria2: " + err.Error() + "\n", false
		}
		defer h.Stop()
		if !WaitPort(p.HysteriaSocksPort, 15*time.Second) {
			return "[FAIL] Hysteria2 未就绪: " + LastErrorLine(h.LogText(4000)) + "\n", false
		}
	}
	return SelfTest(workDir, p, expectEgress)
}

// ProbeProxy 经本地 HTTP 代理做一次轻量连通性探测，用于在两条通道之间择优。
//
// 刻意只请求一个 generate_204、不下载任何正文：开销可以忽略，却足以区分
// 「隧道真的通了」与「本地端口只是在监听」。端口在监听但隧道不通是很常见的情形
// （握手失败、认证被拒、QUIC 被丢包），只探端口会把它误判成可用。
func ProbeProxy(port int, timeout time.Duration) bool {
	u, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	c := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
	return fetchStatus(c, "https://cp.cloudflare.com/generate_204") == "204"
}

func fetchBody(c *http.Client, u string) string {
	resp, err := c.Get(u)
	if err != nil {
		return "ERR:" + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return string(b)
}

func fetchStatus(c *http.Client, u string) string {
	resp, err := c.Get(u)
	if err != nil {
		return "ERR:" + err.Error()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return fmt.Sprintf("%d", resp.StatusCode)
}

// acceptedRoute 从内核日志里取出指定目标最终命中的出站记录。
// Xray 每建立一条连接都会打一行 "<时间戳> from <来源> accepted <目标> [<入站> -> <出站>]"，
// 注意行首带时间戳，所以不能用前缀匹配，这是判断分流是否按预期工作最直接的依据。
func acceptedRoute(text, host string) string {
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.Contains(t, " from ") && strings.Contains(t, " accepted ") && strings.Contains(t, host) {
			return t
		}
	}
	return "(日志中未找到 " + host + " 的路由记录)"
}
