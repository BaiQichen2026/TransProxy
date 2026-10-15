package common

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// 系统代理相关的注册表项。
//
// 直接读写注册表，不再调 reg.exe：reg.exe 是控制台程序，由 GUI 进程拉起时
// Windows 会给它开一个控制台窗口。连接、断开、开机自动还原都要碰这几个值，
// 于是黑框会反复闪——这正是用户反馈的「大黑框很烦」。走 API 则完全没有子进程。
const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// 直连白名单：本地回环、内网网段与不带点的内网主机名，避免它们也被灌进代理。
const proxyOverride = `localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>`

var (
	wininetDLL        = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininetDLL.NewProc("InternetSetOptionW")
)

const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

// notifyWininet 通知 WinINet 配置已变更。
// 只写注册表是不够的——多数已运行的程序不会重新读取，必须发这个通知才能立即生效。
func notifyWininet() {
	_, _, _ = internetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = internetSetOption.Call(0, internetOptionRefresh, 0, 0)
}

func regAdd(name, typ, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开系统代理注册表项失败: %w", err)
	}
	defer k.Close()

	if typ == "REG_DWORD" {
		// 数值自己解析，不用再交给别人。这里必须严格：解析失败要报错，
		// 不能悄悄当成 0——那会让「开启代理」变成「关闭代理」，
		// 用户表现为连上了却完全上不了网。
		n, err := strconv.ParseUint(strings.TrimSpace(value), 0, 32)
		if err != nil {
			return fmt.Errorf("写入注册表 %s 失败: %q 不是合法的 32 位数值", name, value)
		}
		if err := k.SetDWordValue(name, uint32(n)); err != nil {
			return fmt.Errorf("写入注册表 %s 失败: %w", name, err)
		}
		return nil
	}
	if err := k.SetStringValue(name, value); err != nil {
		return fmt.Errorf("写入注册表 %s 失败: %w", name, err)
	}
	return nil
}

// regQueryValue 读取注册表值，不存在时返回空串。
//
// 仍然返回字符串而不是结构化类型，是为了不动下游的 normalizeDword 与
// proxyServerPort：它们本来就是照 reg.exe 的文本输出写的，改成结构化
// 只会把改动面铺到好几处，收益却为零。
func regQueryValue(name string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	// 同一个名字可能是字符串（ProxyServer）也可能是数值（ProxyEnable），两种都试。
	if s, _, err := k.GetStringValue(name); err == nil {
		return s
	}
	if n, _, err := k.GetIntegerValue(name); err == nil {
		// 保持 reg query 的十六进制写法，normalizeDword 认这个格式。
		return fmt.Sprintf("0x%X", n)
	}
	return ""
}

// ProxySnapshot 记录系统代理的原始设置，关闭代理时据此精确还原。
type ProxySnapshot struct {
	Enable   string
	Server   string
	Override string
}

// SnapshotProxy 抓取当前系统代理设置。
func SnapshotProxy() ProxySnapshot {
	return ProxySnapshot{
		Enable:   regQueryValue("ProxyEnable"),
		Server:   regQueryValue("ProxyServer"),
		Override: regQueryValue("ProxyOverride"),
	}
}

// EnableSystemProxy 把系统代理指向本地 HTTP 入站。
func EnableSystemProxy(httpPort int) error {
	if err := regAdd("ProxyServer", "REG_SZ", fmt.Sprintf("127.0.0.1:%d", httpPort)); err != nil {
		return err
	}
	if err := regAdd("ProxyOverride", "REG_SZ", proxyOverride); err != nil {
		return err
	}
	if err := regAdd("ProxyEnable", "REG_DWORD", "1"); err != nil {
		return err
	}
	notifyWininet()
	return nil
}

// DisableSystemProxy 关闭系统代理。
func DisableSystemProxy() error {
	if err := regAdd("ProxyEnable", "REG_DWORD", "0"); err != nil {
		return err
	}
	notifyWininet()
	return nil
}

// CurrentProxy 返回当前生效的代理服务器地址。
func CurrentProxy() string {
	return regQueryValue("ProxyServer")
}

// RestoreProxy 还原到之前保存的设置。
// 原始值读不到时按“关闭代理”处理，避免把系统代理留在一个指向已退出进程的死地址上。
func RestoreProxy(s ProxySnapshot) {
	if s.Server != "" {
		_ = regAdd("ProxyServer", "REG_SZ", s.Server)
	}
	if s.Override != "" {
		_ = regAdd("ProxyOverride", "REG_SZ", s.Override)
	}
	enable := "0"
	if s.Enable != "" {
		enable = normalizeDword(s.Enable)
	}
	_ = regAdd("ProxyEnable", "REG_DWORD", enable)
	notifyWininet()
}

// reg query 输出的 DWORD 形如 0x1 / 0x0。
func normalizeDword(s string) string {
	if strings.HasSuffix(strings.TrimSpace(s), "1") {
		return "1"
	}
	return "0"
}
