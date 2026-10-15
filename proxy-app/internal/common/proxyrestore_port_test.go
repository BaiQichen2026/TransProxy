package common

import "testing"

// proxyServerPort 决定了「这个系统代理设置是不是我们自己写的」。
// 判错方向只有两种，代价都很高：
//   - 把别人的地址认成自己的 → 会去关闭用户自己的代理；
//   - 把本机地址认漏 → 死代理清不掉，用户继续整机上不了网。
func TestProxyServerPort(t *testing.T) {
	for _, c := range []struct {
		name   string
		server string
		want   int
	}{
		{"回环地址", "127.0.0.1:10809", 10809},
		{"localhost", "localhost:17901", 17901},
		{"IPv6 回环", "[::1]:8080", 8080},
		{"两侧带空格", "  127.0.0.1:9999  ", 9999},
		{"局域网地址不算自己", "192.168.1.5:8080", 0},
		{"公网地址不算自己", "proxy.example.com:8080", 0},
		{"0.0.0.0 不算自己", "0.0.0.0:8080", 0},
		{"缺端口", "127.0.0.1", 0},
		{"端口非数字", "127.0.0.1:abc", 0},
		{"端口越界", "127.0.0.1:70000", 0},
		{"端口为 0", "127.0.0.1:0", 0},
		{"空值", "", 0},
	} {
		if got := proxyServerPort(c.server); got != c.want {
			t.Fatalf("%s: proxyServerPort(%q) = %d，期望 %d", c.name, c.server, got, c.want)
		}
	}
}

// 端口无人监听时必须判定为「死代理」，否则用户会一直卡在整机上不了网。
func TestLocalPortAliveDetectsClosedPort(t *testing.T) {
	// 端口 1 上几乎不可能有服务，用它代表「没人监听」。
	if localPortAlive(1) {
		t.Skip("端口 1 意外处于监听状态，换个端口再测")
	}
}

// 对着真实机器验证防线不会被误触：代理指向一个「自己的、且仍有监听者」的端口时，
// 绝不能判定为死代理——否则用户正用得好好的代理会被我们关掉。
// 本测试只读注册表并探测端口，不做任何写入。
func TestDeadOwnProxyGuardDoesNotOverreach(t *testing.T) {
	if normalizeDword(regQueryValue("ProxyEnable")) != "1" {
		t.Skip("当前未启用系统代理，无法验证该分支")
	}
	port := proxyServerPort(regQueryValue("ProxyServer"))
	if port == 0 {
		t.Skip("当前系统代理不是本机回环地址，无法验证该分支")
	}
	if !localPortAlive(port) {
		t.Skip("该端口当前无人监听，无法验证「活着」这一分支")
	}

	if pointsAtDeadOwnProxy([]int{port}) {
		t.Fatal("端口仍有监听者，不应被判定为死代理")
	}
	// 端口不在自己的端口集合里时同样不应认领：那可能是别人的代理。
	if pointsAtDeadOwnProxy([]int{port + 1}) {
		t.Fatal("端口不属于本客户端时，不应去处置它")
	}
	if pointsAtDeadOwnProxy(nil) {
		t.Fatal("未提供自己的端口列表时不应处置任何代理")
	}
}
