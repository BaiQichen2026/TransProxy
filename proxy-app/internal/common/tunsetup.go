package common

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// TUN 模式下系统侧的配置（地址、DNS、路由）全部在这里用 netsh / route 完成，
// 刻意不使用内核的 gateway / autoSystemRoutingTable / autoOutboundsInterface：
//
//  1. 实测这些自动配置在 Windows 上会失败：网卡被建出来了，却没有配上地址
//     （表现为 169.254 开头的 APIPA 地址），也没有任何路由。失败还是静默的，
//     留给用户的唯一现象就是「勾了 TUN 却完全上不了网」，无从排查。
//  2. 自己做的每一步都能回读校验、能明确报错、能干净回滚。宁可多写几十行，
//     也不要一个报不出原因的失败。
//
// 路由设计的关键是防回环：内核自己发往服务器的流量绝不能被送进 TUN，否则死循环。
// 做法是给服务器 IP、DNS 和三个内网网段各加一条经物理网关的路由，
// 它们的前缀都比下面两条接管路由（/1）更具体，因此优先级更高。

type routeSpec struct {
	dest string
	mask string
	gw   string
	ifx  int // 0 表示由系统按网关自行选择接口
}

type TunSetup struct {
	Adapter   string
	Addr      string // 虚拟网卡地址，CIDR 形式
	DNSServer string
	ServerIP  string
	PhysGW    string
	// PhysIP 是物理网卡自身的 IPv4，用于给 direct 出站绑定源地址，见 Profile.SendThrough。
	PhysIP string

	added []routeSpec
}

const (
	tunAdapterName = "TransProxy"
	tunAddress     = "172.19.0.1"
	tunMask        = "255.255.0.0"
	tunMaskCIDR    = "172.19.0.1/16"
	tunDNS         = "223.5.5.5"
)

// NewTunSetup 解析服务器 IP 并读取当前物理默认网关。
// 必须在接管路由之前调用：网关一旦被 TUN 抢走就再也读不到了。
func NewTunSetup(serverHost string) (*TunSetup, error) {
	ips, err := net.LookupIP(serverHost)
	if err != nil {
		return nil, fmt.Errorf("解析服务器地址失败: %w", err)
	}
	var serverIP string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			serverIP = v4.String()
			break
		}
	}
	if serverIP == "" {
		return nil, fmt.Errorf("服务器 %s 没有解析到 IPv4 地址", serverHost)
	}
	gw, ifIP, err := defaultGateway()
	if err != nil {
		return nil, err
	}
	return &TunSetup{
		Adapter:   tunAdapterName,
		Addr:      tunMaskCIDR,
		DNSServer: tunDNS,
		ServerIP:  serverIP,
		PhysGW:    gw,
		PhysIP:    ifIP,
	}, nil
}

// Apply 在网卡出现后完成系统侧配置。任一步失败都会回滚已做的改动并带上具体原因。
func (t *TunSetup) Apply() error {
	if err := t.waitAdapter(15 * time.Second); err != nil {
		return err
	}

	// 1) 地址：这是本次故障的核心，Xray 没有配上，我们自己配。
	if err := run("netsh", "interface", "ipv4", "set", "address",
		"name="+t.Adapter, "static", tunAddress, tunMask); err != nil {
		return fmt.Errorf("设置虚拟网卡地址失败: %w", err)
	}
	if err := run("netsh", "interface", "ipv4", "set", "dnsservers",
		"name="+t.Adapter, "static", t.DNSServer, "primary"); err != nil {
		return fmt.Errorf("设置虚拟网卡 DNS 失败: %w", err)
	}
	if err := t.verifyAddress(); err != nil {
		t.Cleanup()
		return err
	}

	// 2) 绕行路由：必须在接管路由之前加好，否则内核到服务器的那一跳会进 TUN 形成回环。
	bypass := []routeSpec{
		{dest: t.ServerIP, mask: "255.255.255.255", gw: t.PhysGW},
		{dest: t.DNSServer, mask: "255.255.255.255", gw: t.PhysGW},
		{dest: "10.0.0.0", mask: "255.0.0.0", gw: t.PhysGW},
		{dest: "172.16.0.0", mask: "255.240.0.0", gw: t.PhysGW},
		{dest: "192.168.0.0", mask: "255.255.0.0", gw: t.PhysGW},
	}
	for _, r := range bypass {
		if err := t.addRoute(r); err != nil {
			t.Cleanup()
			return fmt.Errorf("添加绕行路由 %s 失败: %w", r.dest, err)
		}
	}

	// 3) 接管路由：用两条 /1 覆盖默认路由，好处是不用改动（也不会破坏）
	//    原有的默认路由，断开时只需删掉这两条即可精确还原。
	idx, err := t.interfaceIndex()
	if err != nil {
		t.Cleanup()
		return err
	}
	for _, dest := range []string{"0.0.0.0", "128.0.0.0"} {
		if err := t.addRoute(routeSpec{dest: dest, mask: "128.0.0.0", gw: tunAddress, ifx: idx}); err != nil {
			t.Cleanup()
			return fmt.Errorf("添加接管路由 %s 失败: %w", dest, err)
		}
	}

	// 4) 回读确认接管路由真的进了表。
	//    只检查「命令没报错」是不够的：路由被系统拒绝但返回 0 的情况并不少见。
	table, err := runOut("route", "print", "-4")
	if err != nil {
		t.Cleanup()
		return fmt.Errorf("读取路由表失败: %w", err)
	}
	for _, dest := range []string{"0.0.0.0", "128.0.0.0"} {
		if !routePresent(table, dest, tunAddress) {
			t.Cleanup()
			return fmt.Errorf("接管路由 %s 未进入路由表", dest)
		}
	}
	return nil
}

// Cleanup 删除自己加过的路由。网卡本身会随内核进程退出而消失，
// 但它带来的系统路由不会，必须显式回收。
func (t *TunSetup) Cleanup() {
	for _, r := range t.added {
		// 删除必须带掩码，否则会误伤系统默认路由：
		// `route delete 0.0.0.0` 不带掩码时命中并删掉的是 0.0.0.0/0（默认路由），
		// 而不是我们加的那条 0.0.0.0/1。这个坑真实发生过——客户端一断开，
		// 用户的整台机器就失去了默认路由，彻底断网且无从排查。
		// 掩码为空或为 0.0.0.0 的一律跳过，这是最后一道保险：本功能只接管/放行
		// 具体网段，永远不该删除默认路由。
		if r.mask == "" || r.mask == "0.0.0.0" {
			continue
		}
		_ = run("route", "delete", r.dest, "mask", r.mask, r.gw)
	}
	t.added = nil
}

// HasDefaultRoute 判断系统当前是否存在 IPv4 默认路由。
// 断开连接后用它自检：TUN 接管期间若因为任何原因弄丢了默认路由，必须立刻报出来，
// 而不是让用户面对一台「能开机但上不了网」的机器。
func HasDefaultRoute() bool {
	out, err := runOut("route", "print", "-4")
	if err != nil {
		return true // 读不到就别误报
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			return true
		}
	}
	return false
}

// Describe 返回本次接管的关键信息，供界面展示与排查。
func (t *TunSetup) Describe() string {
	return fmt.Sprintf("虚拟网卡 %s %s · 经 %s 绕行服务器 %s", t.Adapter, t.Addr, t.PhysGW, t.ServerIP)
}

// ---------- 内部实现 ----------

func (t *TunSetup) addRoute(r routeSpec) error {
	args := []string{"add", r.dest, "mask", r.mask, r.gw, "metric", "1"}
	if r.ifx > 0 {
		args = append(args, "if", fmt.Sprint(r.ifx))
	}
	if err := run("route", args...); err != nil {
		return err
	}
	t.added = append(t.added, r)
	return nil
}

func (t *TunSetup) waitAdapter(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := t.interfaceIndex(); err == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("等待虚拟网卡 %s 出现超时（驱动可能未加载成功，详见内核日志）", t.Adapter)
}

func (t *TunSetup) interfaceIndex() (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("枚举网卡失败: %w", err)
	}
	for _, ifc := range ifaces {
		if strings.EqualFold(ifc.Name, t.Adapter) {
			return ifc.Index, nil
		}
	}
	return 0, fmt.Errorf("未找到网卡 %s", t.Adapter)
}

// verifyAddress 回读网卡地址。配没配上直接决定后续有没有路由，所以必须确认。
func (t *TunSetup) verifyAddress() error {
	ifc, err := net.InterfaceByName(t.Adapter)
	if err != nil {
		return fmt.Errorf("读取虚拟网卡失败: %w", err)
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return fmt.Errorf("读取虚拟网卡地址失败: %w", err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil && v4.String() == tunAddress {
				return nil
			}
		}
	}
	// 这一步失败是最典型的故障：网卡在、地址没配上，外界只会看到 169.254。
	return fmt.Errorf("虚拟网卡 %s 未获得地址 %s（当前地址：%v）", t.Adapter, tunAddress, addrs)
}

// defaultGateway 从路由表里取物理默认网关，并据此反查本机在物理网卡上的地址。
// 后者要拿去给 direct 出站绑定源地址，缺了它国内流量会绕回 TUN 形成死循环。
func defaultGateway() (string, string, error) {
	out, err := runOut("route", "print", "-4")
	if err != nil {
		return "", "", fmt.Errorf("读取路由表失败: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// 形如：0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.100  25
		// 第 4 列并不总是本机地址（部分系统或语言下可能是「在链路上」等文字），
		// 所以第 3 列之后逐列扫描，并与本地接口清单比对——只有真正挂在某个
		// 非 TUN 接口上的地址才会被采纳，这比按列位猜可靠得多。
		if len(f) < 4 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" || !validIPv4(f[2]) {
			continue
		}
		for i := 3; i < len(f); i++ {
			if ip, ok := localInterfaceIP(f[i]); ok {
				return f[2], ip, nil
			}
		}
	}
	return "", "", fmt.Errorf("未找到物理默认网关及其本机地址，无法安全接管路由")
}

// localInterfaceIP 判断某个字符串是否是本机某个非 TUN 接口上的 IPv4。
func localInterfaceIP(s string) (string, bool) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for _, ifc := range ifaces {
		if strings.EqualFold(ifc.Name, tunAdapterName) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && ipnet.IP.Equal(ip) {
				return s, true
			}
		}
	}
	return "", false
}

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func routePresent(table, dest, gw string) bool {
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == dest && f[2] == gw {
			return true
		}
	}
	return false
}

// run 执行命令并丢弃输出（只关心成败）。
func run(name string, args ...string) error {
	_, err := runOut(name, args...)
	return err
}

// hiddenWindow 让子进程不弹出控制台窗口。
func hiddenWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

// runOut 执行命令并把 stderr 一并带回错误里。
// netsh / route 的报错只在 stderr，丢掉它等于把排查线索也丢了。
func runOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.SysProcAttr = hiddenWindow()
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(buf.String())
		if msg == "" {
			msg = err.Error()
		}
		return buf.String(), fmt.Errorf("%s", msg)
	}
	return buf.String(), nil
}
