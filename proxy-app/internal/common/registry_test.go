package common

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// 这三个开关直接改用户的注册表，写错方向的后果都很具体：
// 「取消勾选却照样开机自启」「勾选了却指向一个不存在的 exe」。
// 所以这里对真实的 HKCU 做一轮读写校验——注册表 API 的行为（类型、缺失值、
// 删除不存在的值是否报错）光靠读代码判断不可靠。
//
// 注意：会临时写 HKCU 的 Run / RunOnce，测试结束前恢复原值。

// preserveValue 记下某个值并按需恢复，避免测试污染用户真实设置。
func preserveValue(t *testing.T, root registry.Key, path, name string) {
	t.Helper()
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		// 键不存在：测试结束后直接删掉我们写的值即可
		t.Cleanup(func() {
			if k2, err := registry.OpenKey(root, path, registry.SET_VALUE); err == nil {
				defer k2.Close()
				_ = k2.DeleteValue(name)
			}
		})
		return
	}
	defer k.Close()
	old, _, oldErr := k.GetStringValue(name)
	t.Cleanup(func() {
		k2, err := registry.OpenKey(root, path, registry.SET_VALUE)
		if err != nil {
			return
		}
		defer k2.Close()
		if oldErr == nil {
			_ = k2.SetStringValue(name, old)
		} else {
			_ = k2.DeleteValue(name)
		}
	})
}

func TestAutoStartRoundTrip(t *testing.T) {
	preserveValue(t, registry.CURRENT_USER, runKeyRel, AutoStartValue)

	const exe = `C:\some dir\client.exe`
	const dir = `C:\some dir\work`

	if err := SetAutoStart(exe, dir, true); err != nil {
		t.Fatalf("打开自启失败：%v", err)
	}
	if !AutoStartEnabled(exe, dir) {
		t.Fatal("刚设置完却报告「未生效」")
	}
	// 换个 -dir 必须判定为「不一致」：这正是搬迁目录后自启项指向旧路径的场景，
	// 界面要能如实反映它已经失效。
	if AutoStartEnabled(exe, `D:\other`) {
		t.Error("工作目录对不上时仍报告「已生效」——会把失效的自启项显示成正常")
	}
	if AutoStartEnabled(`D:\moved\client.exe`, dir) {
		t.Error("exe 路径对不上时仍报告「已生效」")
	}

	// 写进去的命令行必须带 -dir，否则程序会退回默认工作目录
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyRel, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("读取自启项失败：%v", err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue(AutoStartValue)
	if err != nil {
		t.Fatalf("自启项没有写进去：%v", err)
	}
	if want := AutoStartCommand(exe, dir); v != want {
		t.Fatalf("自启命令行不对：\n 得到 %q\n 期望 %q", v, want)
	}

	if err := SetAutoStart(exe, dir, false); err != nil {
		t.Fatalf("关闭自启失败：%v", err)
	}
	if AutoStartEnabled(exe, dir) {
		t.Fatal("已经关掉了却仍报告「已生效」")
	}
	// 再关一次不能报错：重复取消是很常见的（每次保存设置都会同步一遍），
	// 删一个不存在的值必须被当成正常情况。
	if err := SetAutoStart(exe, dir, false); err != nil {
		t.Fatalf("重复取消自启报错：%v", err)
	}
}

// 还原启动项用的是 RunOnce 而不是 Run。用错键的后果是「只自启/只还原一次」，
// 用户第二次开机发现行为变了却完全看不出原因，所以把键的位置钉住。
func TestProxyRecoveryUsesRunOnce(t *testing.T) {
	if runOnceKeyRel != `Software\Microsoft\Windows\CurrentVersion\RunOnce` {
		t.Fatalf("还原启动项的键位置被改动了：%s", runOnceKeyRel)
	}
	if runKeyRel != `Software\Microsoft\Windows\CurrentVersion\Run` {
		t.Fatalf("自启键位置被改动了：%s", runKeyRel)
	}
	if runOnceKeyRel == runKeyRel {
		t.Fatal("自启与还原不能共用同一个键")
	}

	preserveValue(t, registry.CURRENT_USER, runOnceKeyRel, runOnceValue)

	if ProxyRecoveryRegistered() {
		UnregisterProxyRecovery()
		if ProxyRecoveryRegistered() {
			t.Fatal("撤销后仍报告「已登记」")
		}
	}

	if err := RegisterProxyRecovery(`C:\a b\client.exe`, `C:\a b\work`); err != nil {
		t.Fatalf("登记还原启动项失败：%v", err)
	}
	if !ProxyRecoveryRegistered() {
		t.Fatal("刚登记完却报告「未登记」")
	}

	// 命令里 exe 路径必须加引号：路径带空格时不加引号，系统会把路径截断成
	// 第一个空格之前的部分，于是每次都去执行一个不存在的文件。
	k, err := registry.OpenKey(registry.CURRENT_USER, runOnceKeyRel, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runOnceValue)
	if err != nil {
		t.Fatal(err)
	}
	if v == "" || v[0] != '"' {
		t.Fatalf("启动项命令没有给 exe 加引号，含空格的路径会被截断：%q", v)
	}
	if !strings.Contains(v, "-"+FlagRestoreProxy) {
		t.Fatalf("启动项命令里缺少 -%s，登录时会走成正常启动：%q", FlagRestoreProxy, v)
	}

	UnregisterProxyRecovery()
	if ProxyRecoveryRegistered() {
		t.Fatal("撤销后仍报告「已登记」")
	}
}

// 系统代理那几个值必须是「字符串读得回、数值也读得回」。
// ProxyEnable 是 DWORD，历史上代码按 reg.exe 的 "0x1" 文本处理，
// 换成注册表 API 之后这层约定不能变——否则 normalizeDword 会判错方向，
// 出现「关代理」被当成「开代理」。
func TestProxyRegistryValueShape(t *testing.T) {
	// 只读，不改动用户设置：这里校验的是读取路径对两种类型的兼容。
	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride"} {
		v := regQueryValue(name)
		_ = v // 存在与否都合法，读不到返回空串即可
	}
	if got := normalizeDword(regQueryValue("ProxyEnable")); got != "0" && got != "1" {
		t.Fatalf("ProxyEnable 归一化结果异常：%q", got)
	}
	if normalizeDword("0x1") != "1" || normalizeDword("0x0") != "0" || normalizeDword("") != "0" {
		t.Fatal("normalizeDword 对 reg query 的十六进制写法处理不对")
	}
}
