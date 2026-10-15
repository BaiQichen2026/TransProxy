package common

import "testing"

// 「记住密码」依赖 DPAPI 加解密。这条测试确认加密后能解回原文，
// 顺带验证 CryptProtectData 的调用约定没写错——那个结构体布局一旦错了，
// 表现是进程直接崩溃而不是返回错误，所以必须有测试兜住。
func TestProtectRoundTrip(t *testing.T) {
	const secret = "A7WYxmXmVnm5"

	enc, err := Protect(secret)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if enc == "" || enc == secret {
		t.Fatalf("加密结果异常（为空或与明文相同）: %q", enc)
	}

	got, err := Unprotect(enc)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if got != secret {
		t.Fatalf("解密结果不匹配: 期望 %q，实际 %q", secret, got)
	}

	// 空值必须优雅处理：用户没勾「记住密码」时走的就是这条路径。
	if s, err := Protect(""); err != nil || s != "" {
		t.Fatalf("空串加密异常: %q %v", s, err)
	}
	if s, err := Unprotect(""); err != nil || s != "" {
		t.Fatalf("空串解密异常: %q %v", s, err)
	}

	// 被篡改的数据必须解不开，而不是解出垃圾。
	if _, err := Unprotect("bm90LWEtcmVhbC1ibG9i"); err == nil {
		t.Fatal("被篡改的数据不该解密成功")
	}
}
