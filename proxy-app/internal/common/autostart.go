package common

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// 开机自启登记在 Run 下，与「登录时还原代理」用的 RunOnce 是**两个不同的键**，
// 不能混用：RunOnce 里的项系统执行一次就会删掉，把自启写进去等于只自启一次，
// 用户第二次开机就再也起不来了，而且完全看不出原因。

// AutoStartValue 是自启项在注册表里的值名。
//
// 刻意用 ASCII 而不是中文名：这是键名，用户看不到，而中文键名在某些系统
// 语言与编码组合下容易出现乱码或写入失败，没必要为了好看冒这个险。
const AutoStartValue = "TransProxyClient"

const runKeyRel = `Software\Microsoft\Windows\CurrentVersion\Run`

// AutoStartCommand 返回要写进自启项的命令行。
//
// 显式带上 -dir：不带的话程序会退回默认的 %LOCALAPPDATA%\TransProxy，
// 一旦用户的安装目录是别的（例如装到了 D 盘并用 -dir 指定），
// 自启起来的就是另一套配置、另一份代理备份，两个实例互相看不见对方的系统代理，
// 排查起来极其费劲。
func AutoStartCommand(exe, workDir string) string {
	return fmt.Sprintf(`"%s" -dir "%s"`, exe, workDir)
}

// SetAutoStart 打开或关闭开机自启。
// enable 为假时会顺手删掉已有登记，避免「界面取消了但开机照旧启动」。
func SetAutoStart(exe, workDir string, enable bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyRel, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开开机自启注册表项失败: %w", err)
	}
	defer k.Close()

	if !enable {
		if err := k.DeleteValue(AutoStartValue); err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("取消开机自启失败: %w", err)
		}
		return nil
	}
	if err := k.SetStringValue(AutoStartValue, AutoStartCommand(exe, workDir)); err != nil {
		return fmt.Errorf("设置开机自启失败: %w", err)
	}
	return nil
}

// AutoStartEnabled 报告自启当前是否真的生效。
//
// 只看「注册表里有没有这个值」是不够的：用户可能把程序挪了目录、
// 或者换了 -dir，注册表里就留下一条指向旧路径的命令——系统每次开机都会去
// 执行一个已经不存在的文件，而界面却还显示「已开启」，用户永远查不出原因。
// 所以这里连命令行一起比对，让界面能如实反映状态。
func AutoStartEnabled(exe, workDir string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyRel, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(AutoStartValue)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(AutoStartCommand(exe, workDir)))
}
