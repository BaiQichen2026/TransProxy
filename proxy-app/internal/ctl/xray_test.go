package ctl

import (
	"path/filepath"
	"strings"
	"testing"
)

// 临时配置文件名必须**保留原扩展名**。
//
// Xray 与 hysteria 都按文件扩展名判断配置格式（Xray 走 serial.GetFormat），
// 写成 config.json.new 内核会认不出是 JSON 而拒绝启动，报的却是一句
// "Failed to get format of ..."，很难反推到是文件名的问题。
//
// 这个坑只在真正部署到新机器时才暴露：控制面与 transctl 写完就改名、不把临时文件
// 交给内核，只有 cmd/transrelay 会跑 `xray -test`。分支节点A第一次部署时踩到了。
func TestCfgTempPathKeepsExtension(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/usr/local/etc/xray/config.json", "/usr/local/etc/xray/config.new.json"},
		{"/etc/hysteria/config.yaml", "/etc/hysteria/config.new.yaml"},
		{"config.json", "config.new.json"},
		{"/tmp/nodot", "/tmp/nodot.new"},
	} {
		got := CfgTempPath(c.in)
		if got != c.want {
			t.Fatalf("CfgTempPath(%q)=%q，期望 %q", c.in, got, c.want)
		}
		// 真正要守的不变式：输入有扩展名时，输出必须留着同一个扩展名。
		// 输入本来就没有扩展名的情形（按扩展名判断格式的内核也不会这么配），
		// 加个 .new 后缀是对的，不做这条断言。
		if filepath.Ext(c.in) != "" && filepath.Ext(got) != filepath.Ext(c.in) {
			t.Fatalf("CfgTempPath(%q) 把扩展名弄丢了: %q", c.in, got)
		}
	}
}

// 用线上那把私钥验证公钥推导结果，必须与内核 `xray x25519 -i <私钥>` 输出的
// "Password (PublicKey)" 完全一致，否则客户端将无法完成 REALITY 认证。
func TestPublicKeyDerivation(t *testing.T) {
	s := ServerSettings{PrivateKey: "8N6r_nTRQBs6X9wNkz3KjQRuV8i1b8R37-xTiZcywFg"}
	got, err := s.PublicKey()
	if err != nil {
		t.Fatalf("推导失败: %v", err)
	}
	const want = "JpLdP8y07KeIIC4UcDQerA3nNfd8-drelm8gQMPhD3g"
	if got != want {
		t.Fatalf("公钥不一致: got %q want %q", got, want)
	}
}

func TestPublicKeyRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "not-base64!", "c2hvcnQ"} {
		s := ServerSettings{PrivateKey: bad}
		if _, err := s.PublicKey(); err == nil {
			t.Fatalf("非法私钥 %q 应当报错", bad)
		}
	}
}

func TestRenderConfigOnlyEnabledUsersAndKeyOptions(t *testing.T) {
	s := DefaultServerSettings()
	users := []User{
		{Name: "alice", UUID: "11111111-1111-4111-8111-111111111111", Enabled: true},
		{Name: "bob", UUID: "22222222-2222-4222-8222-222222222222", Enabled: false},
	}
	b, err := RenderXrayConfig(s, users)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	txt := string(b)

	if !strings.Contains(txt, "alice") {
		t.Error("启用的账号应当出现在配置里")
	}
	if strings.Contains(txt, "bob") {
		t.Error("停用的账号不应出现在配置里")
	}
	// 这几项分别是流量统计、IPv4-only 出口、运行时增删用户所依赖的关键配置，
	// 任意一项缺失都会让对应功能失效，所以在这里锁死。
	for _, key := range []string{"StatsService", "HandlerService", "statsUserUplink", "UseIPv4", InboundTag} {
		if !strings.Contains(txt, key) {
			t.Errorf("配置缺少关键项 %q", key)
		}
	}
}
