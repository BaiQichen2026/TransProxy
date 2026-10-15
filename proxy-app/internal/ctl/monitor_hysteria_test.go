package ctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 通道B 的采集走 hysteria 的统计接口。这里用一个假的接口来验：
// 返回体里除了测试需要的数据，还带了 hysteria 真实会返回的其它字段
// （tx/rx/state 等），确保多出来的字段不会把解析搞坏。
func hyTestServer(t *testing.T, payload string, wantSecret string) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dump/streams" {
			http.NotFound(w, r)
			return
		}
		if wantSecret != "" && r.Header.Get("Authorization") != wantSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)
	return srv, strings.TrimPrefix(srv.URL, "http://")
}

func newHyMonitor(t *testing.T, listen, secret string) *Monitor {
	t.Helper()
	m := NewMonitor(filepath.Join(t.TempDir(), "rec"), filepath.Join(t.TempDir(), "access.log"), nil)
	m.SetHysteria(listen, secret)
	return m
}

const hyPayload = `{"streams":[
  {"state":"established","auth":"qichen","connection":4242,"stream":7,
   "req_addr":"accounts.google.com:443","hooked_req_addr":"","tx":100,"rx":200,
   "initial_at":"2026-09-19T05:00:00.123456789Z","last_active_at":"2026-09-19T05:00:02Z"},
  {"state":"established","auth":"qichen","connection":4242,"stream":8,
   "req_addr":"1.1.1.1:53","tx":10,"rx":20,"initial_at":"2026-09-19T05:00:01Z"},
  {"state":"connecting","auth":"qichen","connection":4242,"stream":9,
   "req_addr":"","tx":0,"rx":0,"initial_at":"2026-09-19T05:00:02Z"}
]}`

// 采集通道B：要拿到账号、目标主机、端口，并标记通道为 B；
// DNS（53 端口）要按噪声丢掉；目标地址还没确定的流不能登记。
func TestCollectHysteriaStreams(t *testing.T) {
	_, listen := hyTestServer(t, hyPayload, "")
	m := newHyMonitor(t, listen, "")

	recs, err := m.fetchHysteriaStreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("应只保留 1 条（DNS 与未定地址的流都要丢掉），实际 %d 条：%+v", len(recs), recs)
	}
	r := recs[0]
	if r.User != "qichen" || r.Host != "accounts.google.com" || r.Port != 443 {
		t.Fatalf("记录内容不对：%+v", r)
	}
	if r.Channel != "B" {
		t.Fatalf("通道标记应为 B，实际 %q", r.Channel)
	}
	// 时间要取流的建立时间，而不是采集时刻——否则记录时间会偏晚，
	// 看起来像是「访问发生在采集那一刻」。
	want := time.Date(2026, 9, 19, 5, 0, 0, 123456789, time.UTC).UnixMicro()
	if r.Time != want {
		t.Fatalf("时间应取 initial_at（%d），实际 %d", want, r.Time)
	}
}

// 统计接口返回的是「当前活跃的流」，同一条流会在连续多次轮询里反复出现，
// 必须去重，否则同一次访问会被记成几十条。
func TestCollectHysteriaDedupesSameStream(t *testing.T) {
	_, listen := hyTestServer(t, hyPayload, "")
	m := newHyMonitor(t, listen, "")

	first, err := m.fetchHysteriaStreams()
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.fetchHysteriaStreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("第一次应采到 1 条，实际 %d", len(first))
	}
	if len(second) != 0 {
		t.Fatalf("同一条流第二次应被去重，实际仍是 %d 条", len(second))
	}
}

// 目标地址还没确定的流不能登记：登记了就永远不会再被采集到，
// 那条访问会彻底消失。
func TestCollectHysteriaDoesNotBurnUnresolvedStream(t *testing.T) {
	m := newHyMonitor(t, "", "")
	m.hyListen = "placeholder"

	// 先给一个地址为空的流
	srv, listen := hyTestServer(t, `{"streams":[{"auth":"qichen","connection":1,"stream":1,"req_addr":"","initial_at":"2026-09-19T05:00:00Z"}]}`, "")
	m.hyListen = listen
	if recs, err := m.fetchHysteriaStreams(); err != nil || len(recs) != 0 {
		t.Fatalf("地址为空的流不该产生记录：%d %v", len(recs), err)
	}
	srv.Close()

	// 同一个 connection/stream 稍后带上了地址，应当被采到
	_, listen2 := hyTestServer(t, `{"streams":[{"auth":"qichen","connection":1,"stream":1,"req_addr":"example.com:443","initial_at":"2026-09-19T05:00:00Z"}]}`, "")
	m.hyListen = listen2
	recs, err := m.fetchHysteriaStreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("同一 stream 拿到地址后应被采集到，实际 %d 条", len(recs))
	}
}

// 统计接口带 secret 时必须把 Authorization 带上，否则会被拒。
func TestCollectHysteriaSendsSecret(t *testing.T) {
	_, listen := hyTestServer(t, hyPayload, "s3cret")
	m := newHyMonitor(t, listen, "s3cret")
	if recs, err := m.fetchHysteriaStreams(); err != nil || len(recs) != 1 {
		t.Fatalf("带正确 secret 应能采集：%d %v", len(recs), err)
	}

	bad := newHyMonitor(t, listen, "wrong")
	if _, err := bad.fetchHysteriaStreams(); err == nil {
		t.Fatal("secret 不对时应当报错，而不是静默返回空")
	}
}

// 未部署双通道时（listen 为空）不该发起任何请求，也不该报错。
func TestCollectHysteriaDisabledWhenNotConfigured(t *testing.T) {
	m := newHyMonitor(t, "", "")
	m.collectHysteria() // 不应 panic，也不该写日志
	if _, failed := m.Stats(); failed != 0 {
		t.Fatalf("未配置时不该产生失败计数：%d", failed)
	}
}

// 接口挂了不能把采集循环带崩，也不能每 2 秒刷一行日志。
func TestCollectHysteriaFailureIsTolerated(t *testing.T) {
	m := newHyMonitor(t, "127.0.0.1:1", "") // 1 端口不会有人监听
	var logs int
	m.logf = func(string, ...any) { logs++ }
	m.collectHysteria()
	m.collectHysteria()
	m.collectHysteria()
	if logs > 1 {
		t.Fatalf("短时间内应抑制重复告警，实际打了 %d 行", logs)
	}
}

// 去重表的容量上限必须真的生效，否则长时间运行后只增不减。
func TestStreamSeenEvictsOldest(t *testing.T) {
	s := newStreamSeen(3)
	for _, k := range []string{"a", "b", "c"} {
		if !s.add(k) {
			t.Fatalf("%s 首次登记应返回 true", k)
		}
	}
	if s.add("a") {
		t.Fatal("重复登记应返回 false")
	}
	s.add("d") // 挤掉最老的 a
	if s.has("a") {
		t.Fatal("超出容量后最老的键应被淘汰")
	}
	if !s.has("d") {
		t.Fatal("新键应在表里")
	}
	if !s.add("a") {
		t.Fatal("a 已被淘汰，重新登记应返回 true（这正是淘汰的预期效果）")
	}
}

// 通道B 的记录要能落盘、能查回来，并且和其它记录共用同一套存储。
func TestHysteriaRecordsAreQueryable(t *testing.T) {
	_, listen := hyTestServer(t, hyPayload, "")
	m := newHyMonitor(t, listen, "")
	recs, err := m.fetchHysteriaStreams()
	if err != nil {
		t.Fatal(err)
	}
	if !m.ingestRecords(recs) {
		t.Fatal("入库失败")
	}
	got, err := m.Query(0, "qichen", "accounts", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Channel != "B" || got[0].Host != "accounts.google.com" {
		t.Fatalf("查回来的记录不对：%+v", got)
	}
	// 落盘内容里也要带通道标记，否则监控端无从区分
	b, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"c":"B"`) {
		t.Fatalf("落盘 JSON 里应带通道标记：%s", b)
	}
}
