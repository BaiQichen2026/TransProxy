package common

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// 配置由手写模板拼出，多一个逗号或少一个花括号都会让内核直接拒绝启动，
// 而且报错信息很不直观，所以两种模式都必须能通过 JSON 解析。
func TestClientConfigIsValidJSON(t *testing.T) {
	for _, tunMode := range []bool{false, true} {
		p := Default()
		p.TunMode = tunMode
		p.UUID = "00000000-0000-0000-0000-000000000000"
		p.PublicKey = "publickey"
		p.ShortID = "shortid"

		raw := ClientConfig(p)
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("TunMode=%v 生成的配置不是合法 JSON: %v\n%s", tunMode, err, raw)
		}

		hasTun := false
		for _, in := range parsed["inbounds"].([]any) {
			if in.(map[string]any)["protocol"] == "tun" {
				hasTun = true
			}
		}
		if hasTun != tunMode {
			t.Fatalf("TunMode=%v 时 tun 入站存在=%v，与预期不符", tunMode, hasTun)
		}
	}
}

// TUN 入站只负责建网卡。地址、DNS、路由必须由客户端自己配（见 tunsetup.go）。
// 这条测试把「自动配置字段不许回来」钉死：一旦回来，就会重现
// 「网卡建好了却没有地址、显示 169.254、什么都没配上」那种静默故障。
func TestTunInboundLeavesSystemConfigToClient(t *testing.T) {
	p := Default()
	p.TunMode = true
	raw := ClientConfig(p)
	for _, unwanted := range []string{
		`"autoSystemRoutingTable"`,
		`"gateway"`,
		`"dns-out"`,
	} {
		if strings.Contains(raw, unwanted) {
			t.Fatalf("TUN 配置不该包含 %s：系统侧配置由客户端负责", unwanted)
		}
	}
	// autoOutboundsInterface 保留：它是防回环的第二道保险。
	// 第一道是我们自己算出的 sendThrough，两者任一有效即可避免流量绕回 TUN。
	if !strings.Contains(raw, `"autoOutboundsInterface": "auto"`) {
		t.Fatal("TUN 配置缺少 autoOutboundsInterface 兜底")
	}
	for _, want := range []string{`"name": "TransProxy"`, `"desc": "TransProxy"`, `"mtu": 1400`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("TUN 配置缺少 %s", want)
		}
	}
}

// 默认网关解析必须对着真实系统的 route print 输出验证。
// 它是绕行路由的基准：解析错了就会把「服务器绕行」指到错误的网关，
// 结果就是内核自己的流量被送进 TUN 形成回环。
func TestDefaultGatewayParsesRealOutput(t *testing.T) {
	gw, ifIP, err := defaultGateway()
	if err != nil {
		t.Fatalf("解析默认网关失败: %v", err)
	}
	if net.ParseIP(gw) == nil || net.ParseIP(gw).To4() == nil {
		t.Fatalf("解析出的网关不是合法 IPv4: %q", gw)
	}
	// 网卡地址同样要解析正确：它会被写进 direct 出站的 sendThrough，
	// 错了就会让国内直连流量绕回 TUN 形成死循环。
	if net.ParseIP(ifIP) == nil || net.ParseIP(ifIP).To4() == nil {
		t.Fatalf("解析出的本机地址不是合法 IPv4: %q", ifIP)
	}
	t.Logf("本机物理默认网关 = %s，网卡地址 = %s", gw, ifIP)
}

// TUN 模式下 direct 出站必须绑定物理网卡地址。
// 少了它，被规则判为直连的国内流量会落进 0.0.0.0/1 接管路由回到 TUN 死循环，
// 现象正是「外网能访问、国内网站全部打不开」。
func TestTunDirectOutboundBindsPhysicalIP(t *testing.T) {
	withTun := Default()
	withTun.TunMode = true
	withTun.SendThrough = "192.168.1.100"
	if raw := ClientConfig(withTun); !strings.Contains(raw, `"sendThrough": "192.168.1.100"`) {
		t.Fatal("TUN 模式下 direct 出站缺少 sendThrough")
	}
	// 普通代理模式不该有：那时没有接管路由，绑源地址只会平白限制可用性。
	noTun := Default()
	noTun.SendThrough = "192.168.1.100"
	if strings.Contains(ClientConfig(noTun), "sendThrough") {
		t.Fatal("普通代理模式不该出现 sendThrough")
	}
}

// 普通代理模式不能引入任何 TUN 相关片段，避免回归。
func TestProxyModeHasNoTunArtifacts(t *testing.T) {
	p := Default()
	raw := ClientConfig(p)
	for _, unwanted := range []string{`"protocol": "tun"`, `"dns-out"`, `"autoSystemRoutingTable"`} {
		if strings.Contains(raw, unwanted) {
			t.Fatalf("普通代理模式不该出现 %s", unwanted)
		}
	}
}

// 本地代理端口默认只监听 127.0.0.1；开启「允许局域网访问」后两个入站都要绑到
// 0.0.0.0，其它设备才能用「本机 IP + 端口」借这条隧道。
// 这条测试防的是「改回硬编码 127.0.0.1」——那正是
// 「本机 IP + 代理端口访问不到」的直接原因。
func TestClientConfigListenAddr(t *testing.T) {
	inboundsOf := func(raw string) map[string]map[string]any {
		t.Helper()
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("配置不是合法 JSON: %v\n%s", err, raw)
		}
		out := map[string]map[string]any{}
		for _, in := range parsed["inbounds"].([]any) {
			m := in.(map[string]any)
			out[m["tag"].(string)] = m
		}
		return out
	}

	def := Default()
	for _, tag := range []string{"socks-in", "http-in"} {
		if got := inboundsOf(ClientConfig(def))[tag]["listen"]; got != ListenLocal {
			t.Fatalf("默认配置下 %s 的 listen = %v，期望 %s", tag, got, ListenLocal)
		}
	}

	lan := Default()
	lan.ListenAddr = ListenAny
	for _, tag := range []string{"socks-in", "http-in"} {
		if got := inboundsOf(ClientConfig(lan))[tag]["listen"]; got != ListenAny {
			t.Fatalf("开启局域网访问后 %s 的 listen = %v，期望 %s", tag, got, ListenAny)
		}
	}
}

// proxyOutboundOf 从生成的配置里取出 tag=proxy 的出站，供两条通道的断言复用。
func proxyOutboundOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("配置不是合法 JSON: %v\n%s", err, raw)
	}
	for _, ob := range parsed["outbounds"].([]any) {
		m := ob.(map[string]any)
		if m["tag"] == "proxy" {
			return m
		}
	}
	t.Fatalf("配置里找不到 tag=proxy 的出站:\n%s", raw)
	return nil
}

// 通道A（REALITY）由内核直接建 VLESS 隧道。
func TestRealityChannelUsesVlessOutbound(t *testing.T) {
	for _, proto := range []string{ProtoReality, ProtoAuto} {
		p := Default()
		p.Protocol = proto
		p.UUID = "00000000-0000-0000-0000-000000000000"
		p.PublicKey = "publickey"
		p.ShortID = "shortid"
		if got := proxyOutboundOf(t, ClientConfig(p))["protocol"]; got != "vless" {
			t.Fatalf("通道 %q 的 proxy 出站协议 = %v，期望 vless", proto, got)
		}
	}
}

// 通道B（Hysteria2）是旁挂结构：内核的 proxy 出站必须指向本机 hysteria 的 SOCKS 端口，
// 而不是自己建隧道——隧道由旁边的 hysteria 进程负责。
func TestHysteriaChannelUsesLocalSocksOutbound(t *testing.T) {
	p := Default()
	p.Protocol = ProtoHysteria
	p.HysteriaEnabled = true
	p.HysteriaPort = 8443
	p.HysteriaObfs = "obfs-placeholder"

	ob := proxyOutboundOf(t, ClientConfig(p))
	if ob["protocol"] != "socks" {
		t.Fatalf("通道B 的 proxy 出站协议 = %v，期望 socks", ob["protocol"])
	}
	servers := ob["settings"].(map[string]any)["servers"].([]any)
	srv := servers[0].(map[string]any)
	if srv["address"] != "127.0.0.1" {
		t.Fatalf("通道B 的 SOCKS 地址 = %v，期望 127.0.0.1", srv["address"])
	}
	if int(srv["port"].(float64)) != p.HysteriaSocksPort {
		t.Fatalf("通道B 的 SOCKS 端口 = %v，期望 %d", srv["port"], p.HysteriaSocksPort)
	}
	// 通道B 不该出现 vless 出站：否则等于两条隧道叠在一起。
	if strings.Contains(ClientConfig(p), `"protocol": "vless"`) {
		t.Fatal("通道B 的配置里不该出现 vless 出站")
	}
}

// 端口缺失时必须兜底成合法端口：生成 `port: 0` 会让内核直接拒绝启动，
// 而且报错信息完全指不到真正的原因。
func TestHysteriaOutboundPortNeverZero(t *testing.T) {
	p := Default()
	p.Protocol = ProtoHysteria
	p.HysteriaSocksPort = 0
	srv := proxyOutboundOf(t, ClientConfig(p))["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if int(srv["port"].(float64)) != DefaultHysteriaSocksPort {
		t.Fatalf("端口缺失时应兜底为 %d，实际 %v", DefaultHysteriaSocksPort, srv["port"])
	}
}

// FromParams 必须把服务端下发的第二条通道参数完整带过来，并给出默认的本机 SOCKS 端口。
func TestFromParamsCarriesHysteriaParams(t *testing.T) {
	p := FromParams(Params{
		Address:         "trans.example.com",
		Port:            443,
		HysteriaEnabled: true,
		HysteriaPort:    8443,
		HysteriaObfs:    "obfs-placeholder",
	}, "00000000-0000-0000-0000-000000000000", ModeSmart, 17900, 17901)

	if !p.HysteriaAvailable() {
		t.Fatal("参数齐全时 HysteriaAvailable 应为 true")
	}
	if p.HysteriaPort != 8443 || p.HysteriaObfs != "obfs-placeholder" {
		t.Fatalf("第二条通道参数未正确带入：端口=%d 混淆=%q", p.HysteriaPort, p.HysteriaObfs)
	}
	if p.HysteriaSocksPort != DefaultHysteriaSocksPort {
		t.Fatalf("本机 SOCKS 端口 = %d，期望 %d", p.HysteriaSocksPort, DefaultHysteriaSocksPort)
	}

	// 服务端没启用时不可用；缺混淆密钥时同样不可用，否则会生成连不上的配置。
	off := FromParams(Params{Address: "trans.example.com", Port: 443}, "", ModeSmart, 17900, 17901)
	if off.HysteriaAvailable() {
		t.Fatal("服务端未启用时 HysteriaAvailable 应为 false")
	}
	half := FromParams(Params{
		Address: "trans.example.com", Port: 443,
		HysteriaEnabled: true, HysteriaPort: 8443,
	}, "", ModeSmart, 17900, 17901)
	if half.HysteriaAvailable() {
		t.Fatal("缺少混淆密钥时 HysteriaAvailable 应为 false")
	}
}

// hysteria 客户端配置是 YAML（不是 JSON），任何模板改动都必须让关键字段仍然齐全，
// 否则 hysteria 会以「配置解析失败」退出，而界面只会看到一个含糊的启动超时。
func TestHysteriaConfigHasRequiredFields(t *testing.T) {
	p := Default()
	p.HysteriaPort = 8443
	p.HysteriaObfs = "obfs-placeholder"
	p.HysteriaSocksPort = DefaultHysteriaSocksPort

	yaml := HysteriaConfig(p, "alice", "pw-placeholder")
	for _, want := range []string{
		"server: proxy.example.com:8443",
		`auth: "alice:pw-placeholder"`,
		"sni: proxy.example.com",
		"type: salamander",
		"password: obfs-placeholder",
		"listen: 127.0.0.1:17902",
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("hysteria 配置缺少 %q:\n%s", want, yaml)
		}
	}
}
