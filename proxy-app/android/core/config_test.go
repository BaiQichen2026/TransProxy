package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// assetDir 指向仓库里已有的分流数据文件。
//
// 分流规则里的 geoip:/geosite: 会在「解析配置」阶段就被读进来，所以校验配置
// 必须有真实的数据文件在场——这也正是 Android 端最容易漏掉的一步：
// 设备上没有这两个文件时，配置会直接被拒绝。
func assetDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "internal", "common", "assets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Skipf("缺少分流数据文件 %s，跳过（%v）", f, err)
		}
	}
	return dir
}

// 测试用的占位凭据。它们不指向任何真实节点，只需满足内核的格式校验：
//   - publicKey 必须是 base64url 能解出 32 字节的字符串（这里就是 0x00..0x1f）；
//   - shortId 必须是十六进制且不超过 16 个字符。
//
// 用真凭据没有意义，反而会把密钥写进代码库。
const (
	testPublicKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	testShortID   = "0123456789abcdef"
)

func sampleParams(t *testing.T, mode string) string {
	t.Helper()
	b, err := json.Marshal(Params{
		Address:     "proxy.example.com",
		Port:        443,
		UUID:        "00000000-0000-0000-0000-000000000000",
		Flow:        "xtls-rprx-vision",
		SNI:         "www.samsung.com",
		PublicKey:   testPublicKey,
		ShortID:     testShortID,
		Fingerprint: "chrome",
		SpiderX:     "/",
		Mode:        mode,
		SocksPort:   17900,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 生成的配置必须能被内核自己的解析器接受。
//
// 这条测试的价值在于：它同时验证了「JSON 语法正确」「协议已注册」
// 「tun 入站的字段名写对了」三件事。配置是手写模板拼出来的，
// 少个逗号或把 MTU 写成 mtu，内核只会在启动时报一句很难懂的错，
// 而那时已经跑到手机上了。
func TestBuildConfigAcceptedByXrayParser(t *testing.T) {
	// 指向真实的数据目录：没有它，geoip:/geosite: 规则会解析失败，
	// 而这正是 Android 端必须提前把数据文件放好的原因。
	t.Setenv(platform.AssetLocation, assetDir(t))

	for _, mode := range []string{ModeSmart, ModeGlobal} {
		raw, err := BuildConfig(sampleParams(t, mode))
		if err != nil {
			t.Fatalf("模式 %s 生成配置失败：%v", mode, err)
		}

		var anyJSON map[string]any
		if err := json.Unmarshal([]byte(raw), &anyJSON); err != nil {
			t.Fatalf("模式 %s 生成的不是合法 JSON：%v\n%s", mode, err, raw)
		}

		cfg, err := serial.LoadJSONConfig(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("模式 %s 的配置被内核拒绝：%v\n%s", mode, err, raw)
		}
		if cfg == nil {
			t.Fatalf("模式 %s 解析出了空配置", mode)
		}
	}

	// 通道B 的配置同样必须能被内核接受：它的 proxy 出站换成了 socks，
	// 是一份不同的配置，不能只验通道A。
	hy := Params{
		Address: "proxy.example.com", Port: 443, UUID: "00000000-0000-0000-0000-000000000000",
		Flow: "xtls-rprx-vision", SNI: "www.samsung.com", PublicKey: testPublicKey,
		ShortID: testShortID, Fingerprint: "chrome", SpiderX: "/", Mode: ModeSmart,
		SocksPort: 17900, Protocol: ProtoHysteria,
		HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "obfs-placeholder",
		HyAuth: "alice:pw-placeholder", HysteriaSocksPort: DefaultHySocksPort,
	}
	b, _ := json.Marshal(hy)
	raw, err := BuildConfig(string(b))
	if err != nil {
		t.Fatalf("通道B 生成配置失败：%v", err)
	}
	if cfg, err := serial.LoadJSONConfig(strings.NewReader(raw)); err != nil {
		t.Fatalf("通道B 的配置被内核拒绝：%v\n%s", err, raw)
	} else if cfg == nil {
		t.Fatal("通道B 解析出了空配置")
	}
}

// tun 入站的存在是这套方案的前提：它一旦丢失，Android 上就没有任何流量会进来。
func TestConfigHasTunAndSocksInbound(t *testing.T) {
	raw, err := BuildConfig(sampleParams(t, ModeSmart))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"protocol": "tun"`, `"tag": "tun-in"`, `"MTU": 1400`, `"tag": "socks-in"`, `"tag": "proxy"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("配置缺少 %s：\n%s", want, raw)
		}
	}
	// MTU 必须是大写：proto 字段名就是 MTU，写成 mtu 会被静默忽略。
	if strings.Contains(raw, `"mtu"`) {
		t.Fatal("MTU 字段名写成了小写，内核会忽略它")
	}
}

// 不开调试端口时不应出现 socks 入站，避免凭空多一个监听端口。
func TestConfigOmitsSocksWhenDisabled(t *testing.T) {
	p := Params{
		Address: "a.example.com", Port: 443, UUID: "u",
		SNI: "s.example.com", PublicKey: "k",
	}
	b, _ := json.Marshal(p)
	raw, err := BuildConfig(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "socks-in") {
		t.Fatal("未指定调试端口时不应生成 socks 入站")
	}
}

// 打开「允许局域网访问」后本机 SOCKS 入站要绑到 0.0.0.0。
// 一直绑 127.0.0.1 的话，局域网内的设备拿「手机 IP + 端口」是连不上的，
// 这正是用户反馈的现象。
func TestSocksInboundListenAddr(t *testing.T) {
	base := Params{
		Address: "a.example.com", Port: 443, UUID: "u",
		SNI: "s.example.com", PublicKey: "k", SocksPort: 17900,
	}

	off, _ := json.Marshal(base)
	rawOff, err := BuildConfig(string(off))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rawOff, `"listen": "127.0.0.1"`) {
		t.Fatalf("默认应只监听 127.0.0.1：\n%s", rawOff)
	}

	base.AllowLAN = true
	on, _ := json.Marshal(base)
	rawOn, err := BuildConfig(string(on))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rawOn, `"listen": "0.0.0.0"`) {
		t.Fatalf("开启局域网访问后应监听 0.0.0.0：\n%s", rawOn)
	}
}

// 通道B（Hysteria2）：内核的 proxy 出站必须指向本机 hysteria 的 SOCKS 端口，
// 而不是自己建隧道——隧道由同进程的 hysteria 客户端负责。
func TestHysteriaChannelUsesLocalSocksOutbound(t *testing.T) {
	hy := Params{
		Address: "trans.example.com", Port: 443, UUID: "u",
		SNI: "s.example.com", PublicKey: "k",
		Protocol:        ProtoHysteria,
		HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "obfs-placeholder",
		HyAuth: "alice:pw-placeholder", HysteriaSocksPort: 17902,
	}
	b, _ := json.Marshal(hy)
	raw, err := BuildConfig(string(b))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("配置不是合法 JSON：%v\n%s", err, raw)
	}
	var proxy map[string]any
	for _, ob := range parsed["outbounds"].([]any) {
		if m := ob.(map[string]any); m["tag"] == "proxy" {
			proxy = m
		}
	}
	if proxy == nil || proxy["protocol"] != "socks" {
		t.Fatalf("通道B 的 proxy 出站应为 socks，实际 %+v", proxy)
	}
	srv := proxy["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if srv["address"] != "127.0.0.1" || int(srv["port"].(float64)) != 17902 {
		t.Fatalf("通道B 的 SOCKS 地址不对：%+v", srv)
	}
	// 通道B 不该出现 vless 出站：否则等于两条隧道叠在一起。
	if strings.Contains(raw, `"protocol": "vless"`) {
		t.Fatal("通道B 的配置里不该出现 vless 出站")
	}
}

// 通道A（默认）仍由内核直接建 REALITY 隧道，不能被改成 socks。
func TestRealityChannelStillUsesVless(t *testing.T) {
	for _, proto := range []string{"", ProtoReality} {
		p := Params{
			Address: "trans.example.com", Port: 443, UUID: "u",
			SNI: "s.example.com", PublicKey: "k", Protocol: proto,
		}
		b, _ := json.Marshal(p)
		raw, err := BuildConfig(string(b))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(raw, `"protocol": "vless"`) {
			t.Fatalf("通道 %q 应生成 vless 出站：\n%s", proto, raw)
		}
		if strings.Contains(raw, `"protocol": "socks"`) {
			t.Fatalf("通道 %q 不该生成 socks 出站", proto)
		}
	}
}

// 端口缺失时兜底到默认值：生成 port:0 会让内核直接拒绝启动，
// 而且报错完全指不到真正的原因。
func TestHysteriaSocksPortNeverZero(t *testing.T) {
	p := Params{
		Address: "trans.example.com", Port: 443, UUID: "u",
		SNI: "s.example.com", PublicKey: "k",
		Protocol:        ProtoHysteria,
		HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "o", HyAuth: "a:b",
		HysteriaSocksPort: 0,
	}
	b, _ := json.Marshal(p)
	raw, err := BuildConfig(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, fmt.Sprintf(`"port": %d`, DefaultHySocksPort)) {
		t.Fatalf("端口缺失时应兜底为 %d：\n%s", DefaultHySocksPort, raw)
	}
}

// 通道B 的参数不齐时必须在本地就报错。留到内核启动才失败的话，
// 用户看到的会是一句与真实原因无关的「配置错误」。
func TestHysteriaRejectsIncompleteParams(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"address": "a.example.com", "port": 443, "uuid": "u",
			"sni": "s.example.com", "publicKey": "k",
			"protocol": ProtoHysteria,
		}
	}
	cases := []struct {
		name  string
		patch map[string]any
	}{
		{"服务端未启用", map[string]any{}},
		{"缺端口", map[string]any{"hysteriaEnabled": true, "hysteriaObfs": "o", "hyAuth": "a:b"}},
		{"缺混淆", map[string]any{"hysteriaEnabled": true, "hysteriaPort": 8443, "hyAuth": "a:b"}},
		{"缺认证", map[string]any{"hysteriaEnabled": true, "hysteriaPort": 8443, "hysteriaObfs": "o"}},
	}
	for _, c := range cases {
		m := base()
		for k, v := range c.patch {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		if _, err := BuildConfig(string(b)); err == nil {
			t.Fatalf("%s：应当报错但通过了", c.name)
		}
	}
}

// 打开的「允许局域网访问」对两条通道都必须生效。
func TestAllowLANAppliesToBothChannels(t *testing.T) {
	for _, proto := range []string{ProtoReality, ProtoHysteria} {
		p := Params{
			Address: "a.example.com", Port: 443, UUID: "u",
			SNI: "s.example.com", PublicKey: "k", SocksPort: 17900,
			AllowLAN: true, Protocol: proto,
			HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "o", HyAuth: "a:b",
		}
		b, _ := json.Marshal(p)
		raw, err := BuildConfig(string(b))
		if err != nil {
			t.Fatalf("通道 %s：%v", proto, err)
		}
		if !strings.Contains(raw, `"listen": "0.0.0.0"`) {
			t.Fatalf("通道 %s 下局域网访问没生效", proto)
		}
	}
}

// 智能分流与全局代理的核心差别：智能模式把国内域名/IP 直连。
// 这条规则决定了「国内站点不走代理」，漏掉会让所有国内流量绕地球一圈。
func TestRoutingRulesByMode(t *testing.T) {
	smart, err := BuildConfig(sampleParams(t, ModeSmart))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(smart, "geoip:cn") || !strings.Contains(smart, "geosite:cn") {
		t.Fatalf("智能分流缺少国内直连规则：\n%s", smart)
	}

	global, err := BuildConfig(sampleParams(t, ModeGlobal))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(global, "geoip:cn") || strings.Contains(global, "geosite:cn") {
		t.Fatal("全局模式不应包含国内直连规则")
	}
	// 两个模式都必须保留内网直连：否则访问局域网设备也会被塞进隧道。
	for _, raw := range []string{smart, global} {
		if !strings.Contains(raw, "geoip:private") {
			t.Fatal("缺少内网直连规则，局域网访问会被代理")
		}
		if !strings.Contains(raw, "block") || !strings.Contains(raw, "bittorrent") {
			t.Fatal("缺少 BT 封锁规则")
		}
	}
}

// 日志级别只认三个值，写错必须退回 warning。
// 放任一个拼错的级别会让内核要么不输出日志、要么把日志缓冲刷爆。
func TestLogLevelFallback(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"", "warning"},
		{"info", "info"},
		{"debug", "debug"},
		{"warning", "warning"},
		{"verbose", "warning"},
		{"INFO", "warning"},
	} {
		p := Params{LogLevel: c.in}
		if got := p.logLevel(); got != c.want {
			t.Fatalf("LogLevel=%q 时得到 %q，期望 %q", c.in, got, c.want)
		}
	}
}

// 缺参数时必须在本地就报错。放任下去，内核只会报一句莫名其妙的启动失败。
func TestBuildConfigRejectsIncompleteParams(t *testing.T) {
	cases := []struct {
		name string
		p    Params
	}{
		{"缺地址", Params{Port: 443, UUID: "u", SNI: "s", PublicKey: "k"}},
		{"端口越界", Params{Address: "a", Port: 70000, UUID: "u", SNI: "s", PublicKey: "k"}},
		{"缺 UUID", Params{Address: "a", Port: 443, SNI: "s", PublicKey: "k"}},
		{"缺公钥", Params{Address: "a", Port: 443, UUID: "u", SNI: "s"}},
		{"缺 SNI", Params{Address: "a", Port: 443, UUID: "u", PublicKey: "k"}},
	}
	for _, c := range cases {
		b, _ := json.Marshal(c.p)
		if _, err := BuildConfig(string(b)); err == nil {
			t.Fatalf("%s：应当报错但通过了", c.name)
		}
	}
}
