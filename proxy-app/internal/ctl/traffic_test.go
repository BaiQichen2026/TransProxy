package ctl

import "testing"

// 这段是内核 statsquery 的**真实输出**（value 是数字而非字符串）。
// 早先的实现用 string 字段接收 value，反序列化直接失败后静默走到文本兜底分支，
// 结果把所有用户用量都读成 0——日志里看不出任何异常。这个用例专门锁死该回归。
const realStatsOutput = `{
    "stat": [
        {
            "name": "user>>>user1>>>traffic>>>uplink",
            "value": 1396
        },
        {
            "name": "user>>>user1>>>traffic>>>downlink",
            "value": 7113
        },
        {
            "name": "user>>>alice>>>traffic>>>uplink",
            "value": 0
        }
    ]
}`

func TestParseTrafficTextRealKernelJSON(t *testing.T) {
	got := parseTrafficText(realStatsOutput)
	if len(got) != 2 {
		t.Fatalf("应解析出 2 个用户，实际 %d 个: %+v", len(got), got)
	}
	if u := got["user1"]; u.Up != 1396 || u.Down != 7113 {
		t.Fatalf("user1 用量解析错误: %+v", u)
	}
	if u, ok := got["alice"]; !ok || u.Up != 0 {
		t.Fatalf("alice 的 0 值也应被记录: %+v", got)
	}
}

func TestParseTrafficTextEmptyResult(t *testing.T) {
	if got := parseTrafficText("{}"); len(got) != 0 {
		t.Fatalf("空结果应解析为 0 条，实际: %+v", got)
	}
}

// 纯文本兜底路径：名称与数值分处两行时也要能正确配对。
func TestParseTrafficTextPlainLines(t *testing.T) {
	raw := "user>>>bob>>>traffic>>>uplink\n2048\nuser>>>bob>>>traffic>>>downlink\n4096\n"
	got := parseTrafficText(raw)
	if u := got["bob"]; u.Up != 2048 || u.Down != 4096 {
		t.Fatalf("文本形态解析错误: %+v", u)
	}
}
