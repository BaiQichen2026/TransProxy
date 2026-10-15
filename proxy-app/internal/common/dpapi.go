package common

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

// 「记住密码」的落盘加密。
//
// 直接用明文把密码写进 settings.json 是不可接受的——那个文件就在用户目录下，
// 任何本地程序都能读到。Windows 自带 DPAPI 正好解决这个问题：它用当前用户的
// 登录凭据派生密钥，同一台机器的同一用户才能解开，连复制到别的机器上都无效。
// 自己造加密算法只会更糟，所以这里就用系统能力。

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32       = syscall.NewLazyDLL("crypt32.dll")
	procProtect   = crypt32.NewProc("CryptProtectData")
	procUnprotect = crypt32.NewProc("CryptUnprotectData")
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree = kernel32.NewProc("LocalFree")
)

// Protect 加密并做 base64 编码，便于存进 JSON。
func Protect(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	in := []byte(plain)
	inBlob := dataBlob{cbData: uint32(len(in)), pbData: &in[0]}
	var outBlob dataBlob

	ret, _, err := procProtect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return "", fmt.Errorf("加密失败: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	buf := unsafe.Slice(outBlob.pbData, outBlob.cbData)
	return base64.StdEncoding.EncodeToString(buf), nil
}

// Unprotect 解开 Protect 的结果。
// 换机器、换用户、或数据被改写都会失败——这正是不用明文的好处。
func Unprotect(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("解码失败: %w", err)
	}
	if len(raw) == 0 {
		return "", nil
	}
	inBlob := dataBlob{cbData: uint32(len(raw)), pbData: &raw[0]}
	var outBlob dataBlob

	ret, _, err := procUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return "", fmt.Errorf("解密失败: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	buf := unsafe.Slice(outBlob.pbData, outBlob.cbData)
	return string(buf), nil
}
