package ctl

import (
	"encoding/json"
	"net/http"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// hashOf 生成一份测试用哈希。
//
// 刻意用 MinCost：这条路径每个用例要跑十来次 bcrypt，用默认 cost 会让测试
// 慢到没人愿意跑，而这里要验证的是「比对结论」而不是「算得够不够慢」。
func hashOf(t *testing.T, pw string) string {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// testHysteriaAuth 按给定的账号表建一个共享认证实现。
// disabled 里的账号模拟「账号存在但已停用」。
func testHysteriaAuth(t *testing.T, users map[string]string, disabled map[string]bool) HysteriaAuth {
	t.Helper()
	return HysteriaAuth{
		Lookup: func(name string) (string, bool) {
			h, ok := users[name]
			if !ok || disabled[name] {
				return "", false
			}
			return h, true
		},
		Lim: NewFailLimiter(nil),
	}
}

func authBody(name, pass string) []byte {
	b, _ := json.Marshal(map[string]any{
		"addr": "203.0.113.9:5555", "auth": name + ":" + pass, "tx": 1,
	})
	return b
}

// 认证判断是通道A 与通道B 共用的那一份（总节点用 Store，分支节点A用内存里的名单），
// 所以这里把它整个钉住：状态码、放行响应、以及「账号不存在与密码错误对外必须不可区分」。
func TestHysteriaAuthServe(t *testing.T) {
	h := testHysteriaAuth(t, map[string]string{"alice": hashOf(t, "pw-alice")}, nil)

	// 请求体不是 JSON：400。这类请求连账号名都取不到，不记失败。
	if code, _ := h.Serve([]byte("not json")); code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应返回 400，实际 %d", code)
	}
	// 拼不出「账号:密码」：401。
	for _, raw := range []string{`{"auth":"alice"}`, `{"auth":":pw"}`, `{"auth":"alice:"}`} {
		if code, _ := h.Serve([]byte(raw)); code != http.StatusUnauthorized {
			t.Fatalf("%s 应返回 401，实际 %d", raw, code)
		}
	}
	// 密码不对 / 账号不存在：必须同一个状态码，否则这个接口可以用来枚举账号。
	for _, raw := range [][]byte{authBody("alice", "wrong"), authBody("nobody", "whatever")} {
		if code, _ := h.Serve(raw); code != http.StatusForbidden {
			t.Fatalf("%s 应返回 403，实际 %d", raw, code)
		}
	}
	// 正确：200，且 id 必须是账号名 —— hysteria 拿它当流量统计的键，
	// 不返回就只能统计到一堆空键。
	code, resp := h.Serve(authBody("alice", "pw-alice"))
	if code != http.StatusOK {
		t.Fatalf("正确密码应返回 200，实际 %d", code)
	}
	if resp["id"] != "alice" || resp["ok"] != true || resp["udp"] != true {
		t.Fatalf("放行响应内容不对: %v", resp)
	}
}

// 停用的账号：Lookup 报 ok=false，与「账号不存在」走同一条拒绝路径。
func TestHysteriaAuthDisabledAccount(t *testing.T) {
	h := testHysteriaAuth(t,
		map[string]string{"bob": hashOf(t, "pw-bob")},
		map[string]bool{"bob": true})
	if code, _ := h.Serve(authBody("bob", "pw-bob")); code != http.StatusForbidden {
		t.Fatalf("停用账号即使密码正确也应拒绝，实际 %d", code)
	}
}

// 限速：这个回调每拒绝一次就做一次 bcrypt 比较，而 hysteria 的端口是对公网的。
// 同一账号连续失败到阈值还不开始拒绝的话，它就是一个免费的密码爆破器
// —— 顺便还能把本机 CPU 打满。
func TestHysteriaAuthRateLimitsBruteForce(t *testing.T) {
	h := testHysteriaAuth(t, map[string]string{"alice": hashOf(t, "pw-alice")}, nil)
	for i := 0; i < loginMaxFail; i++ {
		if code, _ := h.Serve(authBody("alice", "wrong")); code != http.StatusForbidden {
			t.Fatalf("第 %d 次失败应返回 403，实际 %d", i+1, code)
		}
	}
	if code, _ := h.Serve(authBody("alice", "pw-alice")); code != http.StatusTooManyRequests {
		t.Fatalf("达到阈值后即使密码正确也应被限速（429），实际 %d", code)
	}
}

// 成功一次必须把旧账清掉：否则「偶尔输错几次」会一直累加，最终把正常用户锁死。
func TestHysteriaAuthSuccessClearsFailures(t *testing.T) {
	h := testHysteriaAuth(t, map[string]string{"alice": hashOf(t, "pw-alice")}, nil)
	for i := 0; i < loginMaxFail-1; i++ {
		h.Serve(authBody("alice", "wrong"))
	}
	if code, _ := h.Serve(authBody("alice", "pw-alice")); code != http.StatusOK {
		t.Fatalf("还没到阈值，正确密码应当放行，实际 %d", code)
	}
	if d := h.Lim.Blocked("alice", ""); d > 0 {
		t.Fatalf("成功之后不该还带着旧账，剩余封锁 %s", d)
	}
	// 清账之后再来一次失败，仍然不该被封。
	if code, _ := h.Serve(authBody("alice", "wrong")); code != http.StatusForbidden {
		t.Fatalf("成功之后失败计数应清零，实际 %d", code)
	}
}
