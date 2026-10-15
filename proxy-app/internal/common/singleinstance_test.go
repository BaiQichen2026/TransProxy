package common

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// 单实例锁的回归测试。
//
// 这个锁是防止「第二个实例启动时把第一个实例的系统代理在背后关掉」的唯一屏障，
// 判错方向的后果很难看：要么形同虚设（两个实例互相打架），
// 要么把用户正常启动挡在门外（明明没开第二个却说「已在运行」）。
func TestInstanceLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, instanceLockName)

	h1, ok, err := AcquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("第一次取锁就报错：%v", err)
	}
	if !ok {
		t.Fatalf("第一次取锁应当成功，却报告已有实例在运行（锁文件 %s）", lockPath)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("取锁后锁文件应当存在：%v", err)
	}

	// 同一进程再取一次：文件已被自己以「不共享」方式打开，必须拿不到。
	// 这里验的是「会不会误判为可以再起一个实例」。
	h2, ok2, err2 := AcquireInstanceLock(dir)
	if err2 != nil {
		t.Fatalf("第二次取锁报错（应当是干净的「拿不到」）：%v", err2)
	}
	if ok2 {
		t.Error("第二次取锁不该成功：同一个锁文件同时只能有一个持有者")
		_ = windows.CloseHandle(h2)
	}

	// 放掉之后应当能重新取到——否则用户关掉客户端就再也启动不了了。
	if err := windows.CloseHandle(h1); err != nil {
		t.Fatalf("关闭句柄失败：%v", err)
	}
	h3, ok3, err3 := AcquireInstanceLock(dir)
	if err3 != nil {
		t.Fatalf("释放后重新取锁报错：%v", err3)
	}
	if !ok3 {
		t.Error("上一个持有者已退出，这次应当能取到锁")
		return
	}
	_ = windows.CloseHandle(h3)
}

// TestInstanceLockOnExistingFile 覆盖一个容易踩的坑：
// 锁文件是上一轮运行留下的（内容为空、没有任何进程持有），
// 这时必须能正常取锁，不能因为「文件已存在」就误判成已有实例。
func TestInstanceLockOnExistingFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, instanceLockName)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatalf("预置锁文件失败：%v", err)
	}

	h, ok, err := AcquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("残留锁文件导致报错：%v", err)
	}
	if !ok {
		t.Fatal("锁文件是上一轮残留的（无人持有），却被判成「已有实例在运行」")
	}
	_ = windows.CloseHandle(h)
}
