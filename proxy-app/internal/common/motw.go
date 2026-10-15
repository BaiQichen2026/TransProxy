package common

import (
	"errors"
	"os"
	"strings"
)

// zoneIdentifierStream 是 Windows 给「从网上下载的文件」打标记用的备用数据流名。
//
// 浏览器下载完 exe 会往文件上挂这么一条流，内容形如：
//
//	[ZoneTransfer]
//	ZoneId=3
//
// ZoneId=3 就是「Internet 区域」。系统看到它之后，每次运行该文件都会先弹
// 「打开文件 - 安全警告：无法验证发布者。你确定要运行此软件吗？」。
const zoneIdentifierStream = ":Zone.Identifier"

// ClearSelfMarkOfTheWeb 清掉本 exe 上的「来自 Internet」标记。
//
// 用户反馈的「启动时还要弹确认按钮」就是这个标记造成的——它跟我们的代码无关，
// 是 Windows 的下载来源检查；清单里声明的是 asInvoker，全程不提权。
//
// 这个弹窗发生在 exe 被加载**之前**，所以程序自己拦不下第一次。但只要程序能跑
// 起来，就可以顺手把标记删掉，于是**从第二次启动开始不再弹**。
// 想连第一次都不弹，唯一的办法是给 exe 买代码签名证书。
//
// 不需要检查返回值：exe 装在 Program Files 这类只读位置时没有写权限，
// 删除必然失败——那属于正常情况，不该影响启动。
func ClearSelfMarkOfTheWeb() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	_ = clearZoneIdentifier(exe)
}

// clearZoneIdentifier 删除 path 上的 Zone.Identifier 备用数据流。
//
// 流本来就不存在时（文件不是下载来的）返回 nil：「没有标记」和「刚删掉标记」
// 都是调用方想要的结果，不该让调用方去区分。文件系统不支持备用数据流同理。
//
// 只动备用数据流，主数据一个字节都不会碰。
func clearZoneIdentifier(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("路径为空")
	}
	err := os.Remove(path + zoneIdentifierStream)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
