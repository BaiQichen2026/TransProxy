package ctl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testRelaySettings(t *testing.T) RelaySettings {
	t.Helper()
	d := t.TempDir()
	return RelaySettings{
		NodeID: "edge-a", Token: "tok-edgea",
		ControlURL: "https://proxy.example.com:8443",
		ListenPort: 443, Advertise: "203.0.113.7",
		DecoySNI: "www.samsung.com", DecoyTarget: "www.samsung.com:443",
		Flow: "xtls-rprx-vision", Fingerprint: "chrome",
		ConfigPath:   filepath.Join(d, "config.json"),
		IdentityPath: filepath.Join(d, "identity.json"),
		XrayUnit:     "xray",
	}
}

// dig 按路径取值，便于结构化地断言嵌套 JSON（字符串 = 键，整数 = 数组下标）。
func dig(t *testing.T, v any, path ...any) any {
	t.Helper()
	for i, p := range path {
		switch key := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("路径 %v 第 %d 段应当取对象，实际 %T", path, i, v)
			}
			v = m[key]
		case int:
			a, ok := v.([]any)
			if !ok || key >= len(a) {
				t.Fatalf("路径 %v 第 %d 段应当取数组且不越界，实际 %T", path, i, v)
			}
			v = a[key]
		}
	}
	return v
}

func renderRelay(t *testing.T, users ...RelayUser) map[string]any {
	t.Helper()
	raw, err := RenderRelayConfig(
		testRelaySettings(t), RelayIdentity{PrivateKey: "priv-edgea", ShortID: "sid-edgea"}, users)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("渲染结果不是合法 JSON: %v", err)
	}
	return cfg
}

// 落地节点必须**自己出网**：用户要的效果就是「从分支节点A的 IP 访问互联网」。
//
// 这个测试同时守住两件事：出站里必须有 direct，且**不能**出现任何连回出口的
// 中转出站 —— 后者会把出口悄悄变回总节点，而表面上一切都还正常。
func TestRenderRelayExitsDirectly(t *testing.T) {
	cfg := renderRelay(t,
		RelayUser{Name: "bob", UUID: "uuid-b"},
		RelayUser{Name: "alice", UUID: "uuid-a"},
	)

	// 入站（inbounds[0] 是管理接口，[1] 才是 REALITY 入站）：两个账号都在。
	clients := dig(t, cfg, "inbounds", 1, "settings", "clients").([]any)
	if len(clients) != 2 {
		t.Fatalf("入站应有 2 个 client，实际 %d", len(clients))
	}
	// 渲染按名字排序，否则账号集合没变也会因为顺序抖动而白重载内核。
	if got := dig(t, clients[0], "email").(string); got != "alice" {
		t.Fatalf("client 应按名字排序，第一个是 %q", got)
	}
	if got := dig(t, clients[0], "id").(string); got != "uuid-a" {
		t.Fatalf("入站应带真实 UUID（按它记账），实际 %q", got)
	}
	if got := dig(t, cfg, "inbounds", 1, "streamSettings", "realitySettings", "privateKey").(string); got != "priv-edgea" {
		t.Fatalf("入站应使用本机（分支节点A）自己的私钥，实际 %q", got)
	}
	// 管理接口只能监听回环：它带统计与管理能力，不该对外。
	if got := dig(t, cfg, "inbounds", 0, "listen").(string); got != "127.0.0.1" {
		t.Fatalf("管理接口只能监听 127.0.0.1，实际 %q", got)
	}

	outbounds := dig(t, cfg, "outbounds").([]any)
	tags := []string{}
	for _, o := range outbounds {
		if m, ok := o.(map[string]any); ok {
			if tag, ok := m["tag"].(string); ok {
				tags = append(tags, tag)
			}
		}
	}
	// 第一个出站必须是 direct：Xray 拿第一个出站当**默认路由**，而落地节点只有
	// 这一条出网路径。把它排成 block 的后果不是「更安全」，而是**所有用户流量被
	// 黑洞掉** —— 真机上表现为客户端 TLS 握手失败，而两台服务器都不报任何错
	// （access.log 里只会留下 `[relay-in >> block]`，看着还挺正常）。
	if len(tags) == 0 || tags[0] != "direct" {
		t.Fatalf("第一个出站必须是 direct（默认路由＝出网），实际 %v", tags)
	}
	direct := false
	for _, tag := range tags {
		if tag == "direct" {
			direct = true
		}
		if strings.HasPrefix(tag, "core-") {
			t.Fatalf("落地节点不该再有连回出口的中转出站，否则出口又变回总节点了：%v", tags)
		}
	}
	if !direct {
		t.Fatalf("缺少 direct 出站，用户就没法从分支节点A出网：%v", tags)
	}

	// 出口在这台，按用户记账只能自己做，所以统计与访问日志必须开。
	if _, ok := cfg["stats"]; !ok {
		t.Fatal("缺少 stats：那样就统计不到每个账号用了多少")
	}
	if got := dig(t, cfg, "api", "services").([]any); len(got) != 2 {
		t.Fatalf("api 服务没开全：%v", got)
	}
	if _, ok := cfg["policy"].(map[string]any)["levels"]; !ok {
		t.Fatal("缺少按用户记账的 policy")
	}
	if got := dig(t, cfg, "log", "access").(string); got == "" {
		t.Fatal("缺少访问日志路径：面板要回答「谁访问了哪些域名」")
	}
}

// 反过来的回归：配置里不能出现出口节点的任何痕迹。
//
// vnext 是「出站去连另一台 vless 服务器」才有的结构，落地节点不该有它。
func TestRenderRelayHasNoUpstreamReference(t *testing.T) {
	raw, err := RenderRelayConfig(testRelaySettings(t),
		RelayIdentity{PrivateKey: "p", ShortID: "s"},
		[]RelayUser{{Name: "alice", UUID: "uuid-a"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, bad := range []string{"vnext", "proxy.example.com"} {
		if strings.Contains(s, bad) {
			t.Fatalf("落地节点配置里不该出现 %q（那说明又被改回中转了）:\n%s", bad, s)
		}
	}
}

// 一个账号都没授权时必须是「谁都连不上」，而不是留个后门。
//
// 「关」是靠**入站里没有 client** 实现的（内核认不出任何身份），
// 不是靠出站排成黑洞 —— 那条路会把正常账号也一起黑洞掉（见上一条测试的说明）。
func TestRenderRelayWithNoUsersIsClosed(t *testing.T) {
	cfg := renderRelay(t)
	if got := dig(t, cfg, "inbounds", 1, "settings", "clients").([]any); len(got) != 0 {
		t.Fatalf("没有账号时入站不该有 client，实际 %d 个", len(got))
	}
	if got := dig(t, cfg, "outbounds", 0, "tag").(string); got != "direct" {
		t.Fatalf("默认出站应当是 direct（落地节点只有这一条出网路径），实际 %q", got)
	}
}

// hysteriaRelaySettings 是一份「本节点也提供通道B」的配置。
func hysteriaRelaySettings(t *testing.T) RelaySettings {
	t.Helper()
	rs := testRelaySettings(t)
	rs.HysteriaListenPort = 8443
	rs.HysteriaObfs = "obfs-secret"
	rs.HysteriaCert = "/usr/local/etc/transctl/cert/fullchain.pem"
	rs.HysteriaKey = "/usr/local/etc/transctl/cert/privkey.pem"
	rs.HysteriaStatsListen = "127.0.0.1:9999"
	rs.HysteriaStatsSecret = "stats-secret"
	return rs
}

// 通道B 的服务端配置。
//
// 两条是这个测试真正要守住的：认证回调必须指向**本机回环**；
// 配置里**不能出现任何账号凭据** —— 那正是选 HTTP 回调而不是 userpass 的全部理由
// （哈希只留在 transrelay 的内存里，配置文件可以随便备份、拷贝）。
func TestRenderHysteriaConfig(t *testing.T) {
	rs := hysteriaRelaySettings(t)
	raw, err := RenderHysteriaConfig(rs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)

	for _, want := range []string{
		"listen: :8443",
		"cert: " + rs.HysteriaCert,
		"key: " + rs.HysteriaKey,
		"password: obfs-secret",
		"url: http://127.0.0.1:10087" + HysteriaAuthPath,
		"listen: 127.0.0.1:9999",
		"secret: stats-secret",
		"type: http",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("配置里缺少 %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"$2", "userpass", "0.0.0.0"} {
		if strings.Contains(s, bad) {
			t.Fatalf("配置里不该出现 %q（凭据不该进部署文件、认证回调不该对外）:\n%s", bad, s)
		}
	}
}

// 少填关键项必须直接报错，而不是安静地生成一份「客户端连不上」的配置：
// 那种问题的症状只在客户端那边，在这台机器上完全看不出来。
func TestRenderHysteriaConfigRejectsIncomplete(t *testing.T) {
	if _, err := RenderHysteriaConfig(testRelaySettings(t)); err == nil {
		t.Fatal("没配端口时应报错（本节点不提供通道B）")
	}
	base := hysteriaRelaySettings(t)
	for _, mut := range []struct {
		name string
		fn   func(*RelaySettings)
	}{
		{"缺证书", func(r *RelaySettings) { r.HysteriaCert = "" }},
		{"缺私钥", func(r *RelaySettings) { r.HysteriaKey = "" }},
		{"缺混淆口令", func(r *RelaySettings) { r.HysteriaObfs = "" }},
		{"缺统计密钥", func(r *RelaySettings) { r.HysteriaStatsSecret = "" }},
		{"缺统计地址", func(r *RelaySettings) { r.HysteriaStatsListen = "" }},
	} {
		rs := base
		mut.fn(&rs)
		if _, err := RenderHysteriaConfig(rs); err == nil {
			t.Fatalf("%s 时应当被拒绝: %+v", mut.name, rs)
		}
	}
}

// 身份：首次生成、之后稳定复用、权限 0600。

// 重新生成会换掉身份，让所有已发出去的客户端参数立刻失效 —— 这是事故级别的。
func TestRelayIdentityIsStableAndPrivate(t *testing.T) {
	rs := testRelaySettings(t)

	id1, err := LoadOrCreateRelayIdentity(rs.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	if id1.PrivateKey == "" || id1.ShortID == "" {
		t.Fatalf("身份生成不完整: %+v", id1)
	}
	if _, err := id1.PublicKey(); err != nil {
		t.Fatalf("私钥推导公钥失败: %v", err)
	}

	// 权限位只在 Linux 上有意义：Windows 不认 Unix 权限位，Go 对可写文件
	// 一律报 0666，在那边断言 0600 只会得到一个假失败（部署环境是 Linux）。
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(rs.IdentityPath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("身份文件权限应为 0600，实际 %o", perm)
		}
	}

	id2, err := LoadOrCreateRelayIdentity(rs.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id1 {
		t.Fatalf("第二次读取不该重新生成身份：%+v -> %+v", id1, id2)
	}
}

// 配置里少填的项要有合理默认，否则中转节点起不来时只会得到一句含糊的报错。
func TestLoadRelaySettingsDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "relay.json")
	body := `{"nodeId":"edge-a","token":"t","controlUrl":"https://x:8443","advertise":"203.0.113.7"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadRelaySettings(p)
	if err != nil {
		t.Fatal(err)
	}
	if rs.ListenPort != 443 || rs.Flow != "xtls-rprx-vision" || rs.Fingerprint != "chrome" ||
		rs.ConfigPath == "" || rs.IdentityPath == "" || rs.XrayUnit != "xray" || rs.XrayBin == "" {
		t.Fatalf("默认值没补全: %+v", rs)
	}
	// 通道B 的默认值也要补：认证回调的默认地址必须落在回环上，
	// 而单元名必须与官方安装脚本一致（不一致的表现只是「重启失败」）。
	if rs.HysteriaConfigPath != "/etc/hysteria/config.yaml" || rs.HysteriaUnit != "hysteria-server" {
		t.Fatalf("通道B 的路径/单元名默认值不对: %+v", rs)
	}
	if !IsLoopback(rs.HysteriaAuthListen) {
		t.Fatalf("认证回调的默认监听地址必须落在回环上，实际 %q", rs.HysteriaAuthListen)
	}
	if rs.HysteriaEnabled() {
		t.Fatal("没配 hysteriaListenPort 时不该认为本节点提供通道B")
	}
}

// 关键项缺失必须直接报错，而不是带着空值跑起来。
//
// advertise 尤其如此：少了它不会报错，只会表现为「客户端里一直没有这条线路」，
// 在远端机器上极难反推。
func TestLoadRelaySettingsRejectsIncomplete(t *testing.T) {
	for _, body := range []string{
		`{"nodeId":"edge-a"}`,
		`{"nodeId":"edge-a","token":"t","controlUrl":"https://x:8443"}`, // 缺 advertise
	} {
		p := filepath.Join(t.TempDir(), "relay.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRelaySettings(p); err == nil {
			t.Fatalf("这份配置应当被拒绝: %s", body)
		}
	}
}
