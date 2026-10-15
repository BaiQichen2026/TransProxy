package common

import (
	"os"
	"path/filepath"
	"testing"
)

// hasZoneIdentifier 报告文件上是否还挂着「来自 Internet」的标记。
func hasZoneIdentifier(path string) bool {
	_, err := os.Stat(path + zoneIdentifierStream)
	return err == nil
}

func TestClearZoneIdentifierRemovesStream(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "downloaded.exe")
	if err := os.WriteFile(p, []byte("MZ-fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 造一个和浏览器下载后一模一样的标记。ZoneId=3 就是 Internet 区域。
	mark := "[ZoneTransfer]\r\nZoneId=3\r\n"
	if err := os.WriteFile(p+zoneIdentifierStream, []byte(mark), 0o644); err != nil {
		// 不是 NTFS 之类的文件系统会写不了备用数据流，这时测试没有意义。
		t.Skipf("本机文件系统不支持备用数据流，跳过：%v", err)
	}
	if !hasZoneIdentifier(p) {
		t.Fatal("前置条件不成立：标记没写进去")
	}

	if err := clearZoneIdentifier(p); err != nil {
		t.Fatalf("清除失败: %v", err)
	}
	if hasZoneIdentifier(p) {
		t.Fatal("标记还在，下次启动仍会弹安全警告")
	}

	// 关键：只删备用数据流，主数据必须一个字节都没变。
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("目标文件不可读，说明主数据被误删: %v", err)
	}
	if string(b) != "MZ-fake" {
		t.Fatalf("目标文件内容被改动了: %q", b)
	}
}

func TestClearZoneIdentifierIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "from-usb.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 绝大多数 exe 本来就没有标记（从 U 盘、局域网复制来的）。
	// 这种情况必须当成清除成功，不能报错，否则每次启动都要写一条无用日志。
	for i := 1; i <= 3; i++ {
		if err := clearZoneIdentifier(p); err != nil {
			t.Fatalf("第 %d 次清除报错: %v", i, err)
		}
	}
}

func TestClearZoneIdentifierRejectsEmptyPath(t *testing.T) {
	if err := clearZoneIdentifier(""); err == nil {
		t.Fatal("空路径应当报错")
	}
}
