package common

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TUN 模式必须在管理员权限下运行：Xray 创建虚拟网卡时要加载 wintun 驱动，驱动安装是系统级操作。
// 这里不做「静默失败后降级」，而是明确判断并提示，因为 TUN 起不来的现象（能开但没网）
// 比直接报错难排查得多。

// Elevate 以管理员身份重新启动自身，成功返回 true。
// 调用方在返回 true 后应立即退出当前进程，避免两个实例并存。
// extraArgs 会追加到原有命令行之后（用于传递「已尝试提权」标记）。
func Elevate(extraArgs ...string) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	verb := windows.StringToUTF16Ptr("runas")
	file := windows.StringToUTF16Ptr(exe)
	var args *uint16
	all := append(append([]string{}, os.Args[1:]...), extraArgs...)
	if len(all) > 0 {
		// 原样转交命令行参数，否则重启后会丢掉 -dir 之类的设置。
		//
		// 必须逐个按 Windows 规则加引号：直接空格拼接的话，路径里带空格
		// （例如用户名是 "Zhang San"）会被拆成两个参数，重启后就落到
		// 错误的工作目录；更糟的是用户可写路径里塞进 "-" 开头的片段时，
		// 会被当成新增的开关吃掉。
		quoted := make([]string, 0, len(all))
		for _, s := range all {
			quoted = append(quoted, syscall.EscapeArg(s))
		}
		args = windows.StringToUTF16Ptr(strings.Join(quoted, " "))
	}
	ret, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(args)),
		0, uintptr(swShownormal))
	// ShellExecuteW 返回值 <= 32 表示失败，其中常见的是用户点了「否」。
	return ret > 32
}

// Elevated 判断当前进程是否已提权。
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// TunReady 判断 TUN 环境是否就绪：既要已提权，也要 wintun.dll 已就位。
func TunReady(workDir string) bool {
	if !Elevated() {
		return false
	}
	st, err := os.Stat(filepath.Join(workDir, "wintun.dll"))
	return err == nil && st.Size() > 0
}

// TunStatusText 给界面用的简短状态说明。
func TunStatusText(workDir string) string {
	switch {
	case !Elevated():
		return "TUN 不可用：客户端未以管理员身份运行"
	case !TunReady(workDir):
		return "TUN 不可用：虚拟网卡驱动缺失，可点「安装」修复"
	default:
		return "TUN 环境就绪"
	}
}

const swShownormal = 1

var (
	shell32           = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)
