package common

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// 系统代理的还原不能只靠内存里的快照。
//
// 只要进程没走到 disconnect 就消失了——被任务管理器结束、崩溃、或用户开着客户端
// 直接关机重启——注册表里的 ProxyEnable=1 会一直留着，而它指向的本地端口已经
// 没有监听者。现象就是「客户端一退出（或重启后没开客户端），整台机器什么网站
// 都打不开」，连不需要翻墙的站点也打不开，因为流量全被送进一个死地址。
//
// 这里补两道保障：
//  1. 改动系统代理之前，把原始设置落盘到工作目录；
//  2. 登记一个「下次登录时执行一次」的启动项，登录时自动还原并清理自己。
//
// 有了第 2 条，即使客户端再也不会被打开，下次开机登录也会把系统代理还原干净，
// 不会再出现「必须开着客户端才有网」的死循环。

const proxyBackupName = "proxy-backup.json"

// runOnceKey 是当前用户的一次性启动项。用它而不是计划任务：
// 不需要管理员权限，而且系统执行后会自动删除该项，天然就是「一次性」。
//
// 这里同样直接写注册表而不调 reg.exe：这条是在**开机登录时**执行的，
// 那时任何一个控制台子进程都会在用户刚进桌面时弹出一个黑框，
// 观感极差（用户反馈的正是这一点），而此时又恰好没人会去点它。
const (
	runOnceKeyRel = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
	runOnceValue  = "TransProxyRestoreProxy"
)

type proxyBackup struct {
	Enable   string `json:"enable"`
	Server   string `json:"server"`
	Override string `json:"override"`
}

func proxyBackupPath(workDir string) string {
	return filepath.Join(workDir, proxyBackupName)
}

// SaveProxyBackup 在改动系统代理之前把原始设置落盘。
// 必须早于任何注册表改动：顺序反过来就会留下「已经改了但没备份」的窗口，
// 此刻一旦断电，原始设置就再也找不回来了。
func SaveProxyBackup(workDir string, s ProxySnapshot) error {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("创建备份目录失败: %w", err)
	}
	b, err := json.MarshalIndent(proxyBackup{
		Enable:   s.Enable,
		Server:   s.Server,
		Override: s.Override,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(proxyBackupPath(workDir), b, 0o644); err != nil {
		return fmt.Errorf("写入代理备份失败: %w", err)
	}
	return nil
}

// LoadProxyBackup 读取落盘的快照；第二个返回值为 false 表示没有待还原的改动。
func LoadProxyBackup(workDir string) (ProxySnapshot, bool) {
	b, err := os.ReadFile(proxyBackupPath(workDir))
	if err != nil {
		return ProxySnapshot{}, false
	}
	var pb proxyBackup
	if err := json.Unmarshal(b, &pb); err != nil {
		// 文件损坏时当作没有备份：RestoreProxy 对空快照会按「关闭代理」处理，
		// 这比沿用一份读不懂的备份安全。
		return ProxySnapshot{}, false
	}
	return ProxySnapshot{Enable: pb.Enable, Server: pb.Server, Override: pb.Override}, true
}

// ClearProxyBackup 在成功还原之后删除快照文件，
// 免得下次启动把「已经还原过」误判成「上次没还原干净」而重复改动。
func ClearProxyBackup(workDir string) {
	_ = os.Remove(proxyBackupPath(workDir))
}

// RegisterProxyRecovery 登记「下次登录时还原系统代理」。
// 系统会在用户登录时执行一次并自动删除该项。
func RegisterProxyRecovery(exe, workDir string) error {
	cmd := fmt.Sprintf(`"%s" -%s -dir "%s"`, exe, FlagRestoreProxy, workDir)
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runOnceKeyRel, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("登记代理还原启动项失败: %w", err)
	}
	defer k.Close()
	if err := k.SetStringValue(runOnceValue, cmd); err != nil {
		return fmt.Errorf("登记代理还原启动项失败: %w", err)
	}
	return nil
}

// UnregisterProxyRecovery 撤销登记的启动项。
func UnregisterProxyRecovery() {
	k, err := registry.OpenKey(registry.CURRENT_USER, runOnceKeyRel, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(runOnceValue)
}

// ProxyRecoveryRegistered 报告「登录时还原」这条启动项当前是否已登记。
// 供界面显示真实状态：用户可能手工删过，或者上一版留下了一条陈旧的记录。
func ProxyRecoveryRegistered() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runOnceKeyRel, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runOnceValue)
	return err == nil && strings.TrimSpace(v) != ""
}

// RestoreProxyFromBackup 处理「上次没还原干净」的系统代理。
//
// ownPorts 是本客户端自己会监听的本机端口。它只在没有可用备份时用于兜底判断：
// 只有当系统代理确实指向这些端口、且端口已无监听者时，才认定这是我方上次留下的
// 死状态并清除。这个限定是必要的——否则会把用户自己的代理误关掉，
// 例如用户的 v2rayN 恰好还没启动时，它的端口同样是「没有监听者」。
func RestoreProxyFromBackup(workDir string, ownPorts []int) bool {
	if snap, ok := LoadProxyBackup(workDir); ok {
		RestoreProxy(snap)
		ClearProxyBackup(workDir)
		UnregisterProxyRecovery()
		return true
	}

	// 没有可用备份（文件不存在，或文件损坏读不懂）。
	// 损坏时也必须继续往下走：文件存在本身就说明上次改过代理却没还原完，
	// 此时如果直接返回、什么都不做，用户就会一直卡在「整机上不了网」的状态。
	ClearProxyBackup(workDir)
	UnregisterProxyRecovery()
	if pointsAtDeadOwnProxy(ownPorts) {
		_ = DisableSystemProxy()
		return true
	}
	return false
}

// pointsAtDeadOwnProxy 判断系统代理是否正指向「我们自己的、已经没有监听者的端口」。
// 这正是进程被强杀或直接关机后留下的状态：注册表还开着代理，端口后面却什么都没有。
func pointsAtDeadOwnProxy(ownPorts []int) bool {
	if normalizeDword(regQueryValue("ProxyEnable")) != "1" {
		return false
	}
	port := proxyServerPort(regQueryValue("ProxyServer"))
	if port == 0 {
		return false
	}
	for _, p := range ownPorts {
		if p == port {
			return !localPortAlive(port)
		}
	}
	return false
}

// proxyServerPort 从 "127.0.0.1:10809" 这类值里取出端口号。
// 只认本机回环地址：别的地址上的代理不是我们设置的，不该由我们处置。
func proxyServerPort(server string) int {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(server))
	if err != nil {
		return 0
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
	default:
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}

// localPortAlive 判断本机端口上是否有进程在监听。
// 连接失败即视为「没人监听」——对回环地址而言，被拒绝通常就是没有监听者。
func localPortAlive(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// FlagRestoreProxy 是「还原系统代理后退出」的开关名（不含前导横线）。
// 它同时被写进登录启动项、又被客户端解析命令行，两处必须一字不差，
// 所以只在这里定义一次，两边都引用它。
const FlagRestoreProxy = "restore-proxy"
