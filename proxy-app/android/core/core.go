// Package core 是 Android 客户端的内核封装，经 gomobile 编译成 AAR 供 Kotlin 调用。
//
// 边界刻意画得很窄：Kotlin 只负责界面、账号登录与 VpnService；内核的启动、停止与
// 配置生成都在这里。这样分流规则只有一份实现，且与 Windows 端保持同一套语义
// （只代理境外、IPv6 走本机、封锁 BT）。
//
// Android 与 Windows 的关键差异：Android 不能拉起外部进程，内核必须以库的形式
// 跑在应用进程内；虚拟网卡也不是内核自己建的，而是由 VpnService 建好后把 fd 交进来。
package core

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// 注册全部入站/出站协议。少了它，配置里写 "protocol": "tun" 会直接报未知协议。
	_ "github.com/xtls/xray-core/main/distro/all"
)

var (
	mu   sync.Mutex
	inst *core.Instance

	// lb 随包初始化而不是等 Start 再建：通道B先于内核启动，
	// 它握手失败的日志必须同样能被界面看到，否则用户只会看到「连接失败」四个字。
	lb = newLogBuffer()
	// 只在第一次启动时注册日志处理器。重复注册会让每条日志出现两次。
	logOnce sync.Once
)

// appendLog 往界面可见的日志缓冲里追加一行（我们自己产生的事件，非内核日志）。
func appendLog(format string, args ...any) {
	lb.add(fmt.Sprintf(format, args...))
}

// Version 返回内核版本，供界面展示与排查问题。
func Version() string {
	return core.Version()
}

// Start 用给定配置启动内核，并让它接管 tunFd 指向的虚拟网卡。
//
// tunFd 来自 Android 的 VpnService.establish()。Xray 在 Android 上是从环境变量
// xray.tun.fd 读取这个 fd 的（官方约定），所以这里先写环境变量再启动。
//
// assetDir 是 geoip.dat / geosite.dat 所在目录，必须是应用私有目录的真实路径。
// 这一点很容易踩：分流规则里的 geoip:/geosite: 是在「解析配置」阶段就把数据文件读进来的，
// 路径不对会直接报 failed to open file，而不是等到转发时才失败。
//
// 配置由调用方传入而不是在这里拼：便于把将要使用的配置原样落盘/展示，
// 出问题时能直接看到内核到底拿到了什么。
func Start(configJSON string, tunFd int, assetDir string) error {
	mu.Lock()
	defer mu.Unlock()

	if inst != nil {
		return fmt.Errorf("内核已在运行")
	}
	if tunFd <= 0 {
		// fd 无效时提前报错。若放任不管，内核会拿 fd=0 当标准输入，
		// 表现为「启动成功但一个包都过不去」，极难排查。
		return fmt.Errorf("无效的 TUN fd：%d", tunFd)
	}
	if assetDir == "" {
		return fmt.Errorf("未指定分流数据目录（geoip.dat / geosite.dat）")
	}
	if err := os.Setenv(platform.TunFdKey, strconv.Itoa(tunFd)); err != nil {
		return fmt.Errorf("设置 TUN fd 失败：%w", err)
	}
	if err := os.Setenv(platform.AssetLocation, assetDir); err != nil {
		return fmt.Errorf("设置分流数据目录失败：%w", err)
	}

	// 日志收进内存缓冲：Android 上 stderr 不落地，界面需要能直接看到内核在说什么。
	logOnce.Do(func() { log.RegisterHandler(lb) })

	cfg, err := serial.LoadJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("解析配置失败：%w", err)
	}
	i, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("创建内核失败：%w", err)
	}
	if err := i.Start(); err != nil {
		return fmt.Errorf("启动内核失败：%w", err)
	}
	inst = i
	return nil
}

// Stop 关闭内核。可重复调用。
//
// 顺带收掉通道B：两条通道属于同一次隧道，分开收尾迟早会漏掉一条——
// 漏掉的那条会留着一条到服务器的 QUIC 长连接，用户以为已经断开了。
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if inst != nil {
		_ = inst.Close()
		inst = nil
	}
	StopHysteria()
}

// Running 报告内核是否正在运行。
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return inst != nil
}

// Logs 返回最近的日志文本，供界面展示。
func Logs() string {
	return lb.Text()
}

// ClearLogs 清空日志缓冲。
func ClearLogs() {
	lb.Clear()
}

// logBuffer 把内核日志留在内存里，只保留最近若干行。
// 手机上没有方便查看的日志文件，出问题时这几行往往就是唯一的线索。
type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

const logKeep = 400

func newLogBuffer() *logBuffer {
	return &logBuffer{lines: make([]string, 0, logKeep)}
}

func (b *logBuffer) Handle(msg log.Message) {
	b.add(msg.String())
}

// add 追加一行日志，供内核日志与自产事件共用。
func (b *logBuffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
	if len(b.lines) > logKeep {
		// 拷贝到新切片再截断，避免底层数组一直增长。
		b.lines = append([]string(nil), b.lines[len(b.lines)-logKeep:]...)
	}
}

func (b *logBuffer) Text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.lines, "\n")
}

func (b *logBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = b.lines[:0]
}
