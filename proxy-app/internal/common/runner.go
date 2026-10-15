package common

import (
	"bytes"
	"embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// 把内核与规则库直接编进 exe，好处是运行环境零外部依赖，代价是体积约 66MB。
//
//go:embed assets
var assetsFS embed.FS

// wintun.dll 是 TUN 模式的虚拟网卡驱动（官方 v0.14.1，签名方 WireGuard LLC）。
// 随包内嵌而不是运行时下载：既离线可用，也少一个「下载源不可达」的故障点。
//
// hysteria.exe 是第二条通道的内核（官方 v2.12.3）。它平时不启动，
// 只有用户选中「通道B」或「智能优选」回退到它时才被拉起。
var assetFiles = []string{"xray.exe", "geoip.dat", "geosite.dat", "wintun.dll", "hysteria.exe"}

// EnsureAssets 把内嵌资源释放到工作目录。
//
// 每次都逐字节比对，完全一致才跳过写入。早先只比大小，那等于把「文件对不对劲」
// 交给攻击者决定：把 xray.exe 换成同样大小的恶意程序，就能被原样执行；
// TUN 模式下这个进程还是以管理员身份跑起来的。比对要读一遍文件，
// 但读 66MB 仍远比重写 66MB 便宜，启动感知不到差别。
func EnsureAssets(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}
	for _, name := range assetFiles {
		data, err := assetsFS.ReadFile("assets/" + name)
		if err != nil {
			return fmt.Errorf("读取内嵌资源 %s 失败: %w", name, err)
		}
		if err := releaseAsset(dir, name, data); err != nil {
			return err
		}
	}
	return nil
}

// releaseAsset 把一份内嵌资源写到 dir/name；磁盘上内容与内嵌数据一致时跳过写入。
//
// 内容不一致就覆盖，而不是报错退出：这里的目标是「自愈」——用户目录里的
// 内核文件被改坏、被杀软截断、被别的程序占用替换，重新启动一次就该恢复正常。
func releaseAsset(dir, name string, data []byte) error {
	dst := filepath.Join(dir, name)
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(cur, data) {
		return nil
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return fmt.Errorf("释放 %s 失败: %w", name, err)
	}
	return nil
}

// Tunnel 表示一个正在运行的客户端内核进程。
type Tunnel struct {
	cmd     *exec.Cmd
	logFile *os.File
	WorkDir string
	LogPath string

	// 用单独的 goroutine 收尸：这样既能判断进程是否还活着（Alive），
	// 又不会出现 Stop 与收尸两边重复 Wait 打架。
	exited chan struct{}
}

// Start 释放资源、写入配置并拉起内核进程。
func Start(workDir, configJSON string) (*Tunnel, error) {
	if err := EnsureAssets(workDir); err != nil {
		return nil, err
	}

	cfgPath := filepath.Join(workDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(configJSON), 0o644); err != nil {
		return nil, fmt.Errorf("写入配置失败: %w", err)
	}
	return spawn(workDir, "xray.exe", []string{"run", "-config", cfgPath}, "xray.log")
}

// StartHysteria 拉起旁挂的 hysteria 客户端进程（第二条通道）。
//
// 它只做一件事：把本地 SOCKS 端口收到的流量经 QUIC 送到服务器。
// 分流规则、TUN 接管、系统代理全都交给 xray，两条通道因此共用同一套策略，
// 不会出现「换条通道行为就变了」的情况。
func StartHysteria(workDir, configYAML string) (*Tunnel, error) {
	if err := EnsureAssets(workDir); err != nil {
		return nil, err
	}

	cfgPath := filepath.Join(workDir, "hysteria.yaml")
	// 这份配置里含账号密码与混淆密钥，权限收紧到 0600：
	// 同机其他用户不该能随手读到别人的连接凭据。
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0o600); err != nil {
		return nil, fmt.Errorf("写入 hysteria 配置失败: %w", err)
	}
	return spawn(workDir, "hysteria.exe", []string{"client", "-c", cfgPath}, "hysteria.log")
}

// spawn 是两条通道共用的进程拉起逻辑：隐藏窗口、日志落盘、单独收尸。
// 抽出来是为了让 hysteria 也享有与 xray 完全相同的存活判断与停止流程，
// 避免两条通道各写一套、行为不一致。
func spawn(workDir, exe string, args []string, logName string) (*Tunnel, error) {
	logPath := filepath.Join(workDir, logName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("打开日志失败: %w", err)
	}

	cmd := exec.Command(filepath.Join(workDir, exe), args...)
	// 工作目录设为资源所在目录，内核会就近查找 geoip.dat / geosite.dat。
	cmd.Dir = workDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// 不给子进程弹控制台窗口，否则每次启动都会闪一个黑框。
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("启动 %s 失败: %w", exe, err)
	}

	t := &Tunnel{cmd: cmd, logFile: logFile, WorkDir: workDir, LogPath: logPath, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(t.exited)
	}()
	return t, nil
}

// Stop 结束内核进程并关闭日志句柄。
func (t *Tunnel) Stop() {
	if t == nil {
		return
	}
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	if t.exited != nil {
		select {
		case <-t.exited:
		case <-time.After(5 * time.Second):
		}
	}
	if t.logFile != nil {
		_ = t.logFile.Close()
		t.logFile = nil
	}
}

// Alive 判断内核进程是否仍在运行。
// TUN 模式下驱动加载失败会让内核立刻退出，用它才能把「进程已死」和
// 「只是端口还没监听」区分开，否则用户只会看到一个含糊的等待超时。
func (t *Tunnel) Alive() bool {
	if t == nil || t.exited == nil {
		return false
	}
	select {
	case <-t.exited:
		return false
	default:
		return true
	}
}

// EnsureTunDriver 确保虚拟网卡驱动已释放到工作目录。
// 单独抽出来是为了能在用户勾选 TUN 之前就完成检测与「安装」，
// 而不是等连接失败才发现缺驱动。
//
// 判定方式与 EnsureAssets 一致：逐字节比对，不只看大小。
// 这个文件会被以管理员身份运行的内核加载，被换成同样大小的恶意 DLL
// 就等于让攻击者拿到管理员权限，必须校验内容。
func EnsureTunDriver(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建工作目录失败: %w", err)
	}
	data, err := assetsFS.ReadFile("assets/wintun.dll")
	if err != nil {
		return fmt.Errorf("读取内嵌驱动失败: %w", err)
	}
	if err := releaseAsset(dir, "wintun.dll", data); err != nil {
		return fmt.Errorf("释放虚拟网卡驱动失败: %w", err)
	}
	return nil
}

// LogText 读取内核日志尾部，用于界面展示与故障排查。
func (t *Tunnel) LogText(max int) string {
	if t == nil {
		return ""
	}
	b, err := os.ReadFile(t.LogPath)
	if err != nil {
		return ""
	}
	if len(b) > max {
		b = b[len(b)-max:]
	}
	return string(b)
}

// WaitPort 轮询等待本地入站端口就绪。
func WaitPort(port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// LastErrorLine 从内核日志里挑出最值得展示给用户的一行。
// 失败时内核往往先打一堆常规信息，真正的原因在后面，所以从后往前找；
// 找不到明确的错误行就退回最后一行非空内容，总比只说一句「未就绪」有用。
func LastErrorLine(logText string) string {
	lines := strings.Split(strings.TrimSpace(logText), "\n")
	fallback := ""
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" {
			continue
		}
		if fallback == "" {
			fallback = l
		}
		lo := strings.ToLower(l)
		for _, key := range []string{"failed", "error", "unable", "cannot", "拒绝访问", "找不到"} {
			if strings.Contains(lo, key) {
				return l
			}
		}
	}
	if fallback == "" {
		return "内核未就绪，详情见工作目录下的 xray.log"
	}
	return fallback
}
