package common

import (
	"os"
	"path/filepath"
	"testing"
)

// 备份能原样读回，是「异常退出后能还原」的前提。
// 这里刻意覆盖空值：原始状态本来就可能是「从未设过代理」，
// 空值必须被当成有效内容保存下来，而不是被当成「没有备份」。
func TestProxyBackupRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := ProxySnapshot{
		Enable:   "1",
		Server:   "127.0.0.1:10809",
		Override: "localhost;127.*",
	}
	if err := SaveProxyBackup(dir, want); err != nil {
		t.Fatalf("保存备份失败: %v", err)
	}

	got, ok := LoadProxyBackup(dir)
	if !ok {
		t.Fatal("备份文件存在时应能读回")
	}
	if got != want {
		t.Fatalf("读回的备份 = %+v，期望 %+v", got, want)
	}
}

// 原始状态是「未启用代理」时，三个字段都可能是空串，这仍然是有效备份。
func TestProxyBackupKeepsEmptyOriginal(t *testing.T) {
	dir := t.TempDir()
	if err := SaveProxyBackup(dir, ProxySnapshot{}); err != nil {
		t.Fatalf("保存空备份失败: %v", err)
	}
	got, ok := LoadProxyBackup(dir)
	if !ok {
		t.Fatal("空备份也应被识别为「有一份待还原的原始设置」")
	}
	if got != (ProxySnapshot{}) {
		t.Fatalf("空备份读回 = %+v，期望全空", got)
	}
}

// 没有备份文件时必须报告「无需还原」，否则每次启动都会去改注册表。
func TestLoadProxyBackupMissing(t *testing.T) {
	if _, ok := LoadProxyBackup(t.TempDir()); ok {
		t.Fatal("没有备份文件时不应报告有待还原的改动")
	}
}

// 备份文件损坏时按「没有备份」处理：RestoreProxy 对空快照会退化为
// 「关闭系统代理」，这比沿用一份读不懂的内容安全。
func TestLoadProxyBackupCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, proxyBackupName), []byte("{不是合法 JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadProxyBackup(dir); ok {
		t.Fatal("备份损坏时应按「没有备份」处理")
	}
}

// 还原完成后必须清掉备份文件，否则下次启动会把「已还原」误判成
// 「上次没还原干净」而再次改写注册表。
func TestClearProxyBackup(t *testing.T) {
	dir := t.TempDir()
	if err := SaveProxyBackup(dir, ProxySnapshot{Enable: "1"}); err != nil {
		t.Fatal(err)
	}
	ClearProxyBackup(dir)
	if _, ok := LoadProxyBackup(dir); ok {
		t.Fatal("清除后不应还能读到备份")
	}
	// 重复清除不应报错（退出流程可能走多次）。
	ClearProxyBackup(dir)
}

// 对着真实机器的当前设置做一次「快照→落盘→读回」。
// ProxyOverride 是一长串带分号的规则，最怕被截断或转义出错——
// 一旦还原时写回一份残缺的值，用户原有的直连白名单就丢了。
// 本测试只读写临时文件，不碰注册表。
func TestProxySnapshotSerializationIsLossless(t *testing.T) {
	orig := SnapshotProxy()
	if orig.Server == "" && orig.Override == "" && orig.Enable == "" {
		t.Skip("当前未设置系统代理，无从验证长串往返")
	}

	dir := t.TempDir()
	if err := SaveProxyBackup(dir, orig); err != nil {
		t.Fatalf("保存备份失败: %v", err)
	}
	got, ok := LoadProxyBackup(dir)
	if !ok {
		t.Fatal("应能读回备份")
	}
	if got != orig {
		t.Fatalf("往返后不一致：\n原始=%+v\n读回=%+v", orig, got)
	}
	if len(orig.Override) > 0 && len(got.Override) != len(orig.Override) {
		t.Fatalf("ProxyOverride 长度变了：原始 %d，读回 %d", len(orig.Override), len(got.Override))
	}
	t.Logf("快照往返正常：Enable=%q Server=%q Override=%d 字符",
		got.Enable, got.Server, len(got.Override))
}
