package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// 客户端每次启动都会先「还原上次残留的系统代理」。这个动作在没有互斥的情况下
// 是有害的：第二个实例一启动就把注册表里的代理关掉，而第一个实例还连着，
// 用户看到的现象是「用着用着突然上不了网」，且完全找不到原因。
//
// 所以进程一开始就取一份独占锁，拿不到就说明已经有一个实例在跑。
// 锁用文件句柄实现，由操作系统在进程结束时自动释放——包括被强杀的情况，
// 因此不会出现「上次没退干净导致再也启动不了」的死锁。

// instanceLockName 是锁文件名，放在工作目录下。
const instanceLockName = "client.lock"

// AcquireInstanceLock 尝试取得本机的客户端独占权。
//
// 第二个返回值 false 表示已有实例在运行，调用方应当直接退出，
// 并且在退出前不要碰任何系统状态（尤其不要还原系统代理）。
// 返回的句柄必须在整个进程生命周期内保持打开，关闭即等于放锁。
func AcquireInstanceLock(workDir string) (windows.Handle, bool, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return 0, false, fmt.Errorf("创建工作目录失败: %w", err)
	}
	path := filepath.Join(workDir, instanceLockName)
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false, err
	}
	// 共享模式给 0：文件已被打开时，第二次打开必然失败。
	// 这比 LockFileEx 更省事，语义也更直接——「这个文件在本机只允许一个打开者」。
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("创建实例锁失败: %w", err)
	}
	return h, true, nil
}
