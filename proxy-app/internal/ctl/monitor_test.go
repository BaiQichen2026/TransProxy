package ctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 解析用的是线上真实日志行。这段解析一旦写错，表现是监控页面静默地什么都看不到，
// 而不是报错，所以必须拿样本钉住。
func TestParseAccessLineRealSamples(t *testing.T) {
	cases := []struct {
		name string
		line string
		want AccessRecord
	}{
		{
			name: "通道A 命中域名的普通 TCP",
			line: `2026/09/19 04:11:19.362675 from 27.187.241.248:41478 accepted tcp:rr10---sn-n3cgv5qc5oq-bh2dd.googlevideo.com:443 [reality-in >> direct] email: qichen`,
			want: AccessRecord{
				User: "qichen", Host: "rr10---sn-n3cgv5qc5oq-bh2dd.googlevideo.com",
				Port: 443, Network: "tcp", Outbound: "direct", Source: "27.187.241.248",
			},
		},
		{
			// 来源地址带 tcp: 前缀、目标是 UDP（DNS 查询），两种变形同时出现。
			name: "来源带 tcp 前缀的 UDP",
			line: `2026/09/19 04:11:23.365107 from tcp:27.187.241.248:41534 accepted udp:1.1.1.1:53 [reality-in >> direct] email: qichen`,
			want: AccessRecord{
				User: "qichen", Host: "1.1.1.1", Port: 53,
				Network: "udp", Outbound: "direct", Source: "27.187.241.248",
			},
		},
		{
			name: "IPv6 目标取最后一个冒号切端口",
			line: `2026/09/19 04:11:20.000000 from 10.0.0.1:1234 accepted tcp:[2001:db8::1]:443 [reality-in >> direct] email: alice`,
			want: AccessRecord{
				User: "alice", Host: "2001:db8::1", Port: 443,
				Network: "tcp", Outbound: "direct", Source: "10.0.0.1",
			},
		},
	}

	for _, c := range cases {
		got, ok := ParseAccessLine(c.line)
		if !ok {
			t.Fatalf("%s：应当解析成功", c.name)
		}
		c.want.Time = got.Time // 时间单独校验，见下
		if got != c.want {
			t.Fatalf("%s：\n得到 %+v\n期望 %+v", c.name, got, c.want)
		}
		if got.Time == 0 {
			t.Fatalf("%s：时间没有解析出来", c.name)
		}
	}
}

// 时间戳必须按本地时区解析。用时区无关的写法重新算一遍期望值。
func TestParseAccessLineTime(t *testing.T) {
	rec, ok := ParseAccessLine(`2026/09/19 04:11:19.362675 from 1.2.3.4:1 accepted tcp:a.com:443 [reality-in >> direct] email: u`)
	if !ok {
		t.Fatal("应当解析成功")
	}
	want := time.Date(2026, 9, 19, 4, 11, 19, 362675000, time.Local).UnixMicro()
	if rec.Time != want {
		t.Fatalf("时间 = %d，期望 %d", rec.Time, want)
	}
}

// 同一毫秒内的多条记录必须仍然能区分开。
//
// 内核日志是微秒精度，而一次 DNS 突发会在同一毫秒里产生好几条一模一样的记录
// （域名、端口、协议全同）。早先按毫秒存，监控端做增量去重时把这些真实记录
// 当成重复丢掉了——实测 611 条被并成 371 条。这条测试把精度钉死在微秒。
func TestSameMillisecondRecordsStayDistinct(t *testing.T) {
	recs := []AccessRecord{}
	for _, us := range []string{"100001", "100002", "100003"} {
		line := "2026/09/19 04:11:19." + us +
			" from 27.187.241.248:41478 accepted udp:1.1.1.1:53 [reality-in >> direct] email: qichen"
		r, ok := ParseAccessLine(line)
		if !ok {
			t.Fatalf("应当解析成功：%s", line)
		}
		recs = append(recs, r)
	}
	if recs[0].Time == recs[1].Time || recs[1].Time == recs[2].Time {
		t.Fatalf("同一毫秒内的记录被解析成了同一个时间戳：%d %d %d",
			recs[0].Time, recs[1].Time, recs[2].Time)
	}
	// 三条记录落在同一毫秒里，但时间戳必须互不相同
	ms := map[int64]bool{}
	for _, r := range recs {
		ms[r.Time/1000] = true
	}
	if len(ms) != 1 {
		t.Fatalf("样本应当落在同一毫秒内，实际跨了 %d 个毫秒", len(ms))
	}
}

// DNS 记录里只有「查询发给了哪个解析器」，没有「查了什么域名」，
// 对监控毫无价值，采集时就要丢掉。但 UDP 443（QUIC）是真实访问，必须保留。
//
// 853 是 DNS over TLS / DNS over QUIC 的端口。手机把「私人 DNS」设成 1.1.1.1 时
// 会不停地连 1.1.1.1:853，页面上就整屏都是 1.1.1.1——信息量和 53 端口那条一样，同样该丢。
func TestMonitorDropsDNSNoise(t *testing.T) {
	m, logPath := newTestMonitor(t)
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	body := ts + " from 1.2.3.4:1 accepted udp:1.1.1.1:53 [reality-in >> direct] email: alice\n" +
		ts + " from 1.2.3.4:2 accepted udp:8.8.8.8:53 [reality-in >> direct] email: alice\n" +
		ts + " from 1.2.3.4:5 accepted tcp:1.1.1.1:853 [reality-in >> direct] email: alice\n" +
		ts + " from 1.2.3.4:6 accepted udp:1.1.1.1:853 [reality-in >> direct] email: alice\n" +
		ts + " from 1.2.3.4:3 accepted tcp:example.com:443 [reality-in >> direct] email: alice\n" +
		ts + " from 1.2.3.4:4 accepted udp:example.com:443 [reality-in >> direct] email: alice\n"

	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m.tailOnce(0)

	recs, err := m.Query(0, "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("应只保留 2 条（TCP 443 与 QUIC），实际 %d 条：%+v", len(recs), recs)
	}
	for _, r := range recs {
		if r.Port == 53 || r.Port == 853 {
			t.Fatalf("DNS 记录没被过滤掉：%+v", r)
		}
	}
	// 被过滤掉的记录不该被算成解析失败
	if _, failed := m.Stats(); failed != 0 {
		t.Fatalf("过滤 DNS 不该计入解析失败，实际 %d", failed)
	}
}

// 没有 email 的行不属于任何账号，必须被丢掉：控制面自己的 API 调用也在同一个日志里。
func TestParseAccessLineSkipsNonUserTraffic(t *testing.T) {
	for _, line := range []string{
		`2026/09/19 04:11:37.517078 from 127.0.0.1:41674 accepted tcp:127.0.0.1:10085 [api -> api]`,
		`2026/09/19 04:11:37.517078 from 127.0.0.1:41674 accepted tcp:127.0.0.1:10085 [reality-in >> direct]`,
		`2026/09/19 04:11:37.517078 from 127.0.0.1:1 accepted tcp:1.1.1.1:443 [reality-in >> direct] email: `,
		`这不是日志行`,
		``,
	} {
		if _, ok := ParseAccessLine(line); ok {
			t.Fatalf("不该解析成功：%q", line)
		}
	}
}

func newTestMonitor(t *testing.T) (*Monitor, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	return NewMonitor(filepath.Join(dir, "rec"), logPath, nil), logPath
}

// 从内核日志增量读入，并能按账号/主机查回来。
func TestMonitorTailAndQuery(t *testing.T) {
	m, logPath := newTestMonitor(t)
	now := time.Now()

	line := func(off time.Duration, user, host string) string {
		return time.Now().Add(off).Format("2006/01/02 15:04:05.000000") +
			" from 9.9.9.9:1234 accepted tcp:" + host + ":443 [reality-in >> direct] email: " + user
	}
	body := line(-3*time.Second, "alice", "a.example.com") + "\n" +
		line(-2*time.Second, "bob", "b.example.com") + "\n" +
		line(-1*time.Second, "alice", "c.example.com") + "\n"
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = now

	off := m.tailOnce(0)
	if off != int64(len(body)) {
		t.Fatalf("偏移 = %d，期望 %d", off, len(body))
	}
	if ing, _ := m.Stats(); ing != 3 {
		t.Fatalf("写入条数 = %d，期望 3", ing)
	}

	// 再读一次不该重复计入：偏移量已经推进到文件末尾。
	m.tailOnce(off)
	if ing, _ := m.Stats(); ing != 3 {
		t.Fatalf("重复读取不该再计入，实际 %d", ing)
	}

	all, err := m.Query(0, "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("查到 %d 条，期望 3", len(all))
	}
	byAlice, err := m.Query(0, "alice", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(byAlice) != 2 {
		t.Fatalf("alice 的记录 = %d 条，期望 2", len(byAlice))
	}
	byHost, err := m.Query(0, "", "c.example", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(byHost) != 1 || byHost[0].Host != "c.example.com" {
		t.Fatalf("按主机过滤结果不对：%+v", byHost)
	}

	// 内存里的最近记录应当也拿到了
	if r := m.Recent(10); len(r) != 3 {
		t.Fatalf("Recent 返回 %d 条，期望 3", len(r))
	}
}

// 内核可能正好写到一半，半行必须留到下一轮，不能被当成坏行丢掉。
func TestMonitorTailWaitsForCompleteLine(t *testing.T) {
	m, logPath := newTestMonitor(t)
	full := time.Now().Format("2006/01/02 15:04:05.000000") +
		" from 1.2.3.4:1 accepted tcp:partial.example.com:443 [reality-in >> direct] email: alice\n"
	half := full[:len(full)/2]

	if err := os.WriteFile(logPath, []byte(half), 0o600); err != nil {
		t.Fatal(err)
	}
	if off := m.tailOnce(0); off != 0 {
		t.Fatalf("只有半行时偏移不该推进，实际 %d", off)
	}
	if ing, _ := m.Stats(); ing != 0 {
		t.Fatalf("半行不该被计入，实际 %d", ing)
	}

	// 补全后应当能读到完整的一条
	if err := os.WriteFile(logPath, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	if off := m.tailOnce(0); off != int64(len(full)) {
		t.Fatalf("补全后偏移 = %d，期望 %d", off, len(full))
	}
	if ing, _ := m.Stats(); ing != 1 {
		t.Fatalf("补全后应计入 1 条，实际 %d", ing)
	}
}

// 日志被外部轮转（文件变小）时必须从头再来，否则会一直读不到新内容。
func TestMonitorResetsOffsetOnRotation(t *testing.T) {
	m, logPath := newTestMonitor(t)
	line := func(host string) string {
		return time.Now().Format("2006/01/02 15:04:05.000000") +
			" from 1.2.3.4:1 accepted tcp:" + host + ":443 [reality-in >> direct] email: alice\n"
	}
	if err := os.WriteFile(logPath, []byte(line("one.example.com")+line("two.example.com")), 0o600); err != nil {
		t.Fatal(err)
	}
	off := m.tailOnce(0)

	// 模拟 logrotate：文件被换成更短的新文件
	if err := os.WriteFile(logPath, []byte(line("three.example.com")), 0o600); err != nil {
		t.Fatal(err)
	}
	m.tailOnce(off)

	recs, err := m.Query(0, "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		if r.Host == "three.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("轮转后的新内容没有被读到")
	}
}

// 超过保留期的按天文件要被删掉，当天与保留期内的必须留下。
func TestMonitorRetention(t *testing.T) {
	m, _ := newTestMonitor(t)
	_ = os.MkdirAll(m.dir, 0o700)

	today := time.Now().Format("2006-01-02")
	old := time.Now().AddDate(0, 0, -accessRetainDays-2).Format("2006-01-02")
	recent := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	for _, d := range []string{today, recent, old} {
		if err := os.WriteFile(m.dayFile(d), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m.cleanup()

	if _, err := os.Stat(m.dayFile(old)); !os.IsNotExist(err) {
		t.Fatal("过期文件没有被删除")
	}
	for _, d := range []string{today, recent} {
		if _, err := os.Stat(m.dayFile(d)); err != nil {
			t.Fatalf("该保留的文件 %s 被删了：%v", d, err)
		}
	}
}

// 聚合统计：域名 TopN 与每个账号的条数。
func TestMonitorAggregate(t *testing.T) {
	m, logPath := newTestMonitor(t)
	recs := []AccessRecord{
		{Time: time.Now().UnixMicro(), User: "alice", Host: "x.com", Port: 443, Network: "tcp"},
		{Time: time.Now().UnixMicro(), User: "alice", Host: "x.com", Port: 443, Network: "tcp"},
		{Time: time.Now().UnixMicro(), User: "bob", Host: "y.com", Port: 443, Network: "tcp"},
	}
	if err := m.writeRecords(recs); err != nil {
		t.Fatal(err)
	}
	_ = logPath

	hosts, byUser, total, err := m.Aggregate(time.Now().Add(-time.Hour).UnixMicro(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("总条数 = %d，期望 3", total)
	}
	if len(hosts) == 0 || hosts[0].Host != "x.com" || hosts[0].Count != 2 {
		t.Fatalf("域名排行不对：%+v", hosts)
	}
	if byUser["alice"] != 2 || byUser["bob"] != 1 {
		t.Fatalf("按账号统计不对：%+v", byUser)
	}

	// 只看 alice 时不该把 bob 的算进来
	_, byUserAlice, totalAlice, err := m.Aggregate(time.Now().Add(-time.Hour).UnixMicro(), "alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	if totalAlice != 2 || len(byUserAlice) != 1 {
		t.Fatalf("按账号过滤后统计不对：total=%d byUser=%+v", totalAlice, byUserAlice)
	}
}

// 控制面自己的 api 调用混在同一个日志里，跳过它们不该被记成「解析失败」——
// 否则 parseFailed 会长期非零，这个指标就不能用来发现内核换日志格式了。
func TestMonitorDoesNotCountControlPlaneLinesAsFailures(t *testing.T) {
	m, logPath := newTestMonitor(t)
	body := ""
	for i := 0; i < 5; i++ {
		body += time.Now().Format("2006/01/02 15:04:05.000000") +
			" from 127.0.0.1:46898 accepted tcp:127.0.0.1:10085 [api -> api]\n"
	}
	// 再加一条真正畸形的用户记录：这条必须被算作失败。
	body += "2026/09/19 04:44:29.753465 from 1.2.3.4:1 这条不合法 email: alice\n"

	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m.tailOnce(0)

	ing, failed := m.Stats()
	if ing != 0 {
		t.Fatalf("不该解析出记录，实际 %d 条", ing)
	}
	if failed != 1 {
		t.Fatalf("失败计数 = %d，期望 1（只有那条畸形用户记录）", failed)
	}
}

// 监控接口必须只认管理员令牌。这条测试防的是「用用户令牌也能读到所有人的记录」
// 这种最糟糕的混用。
func TestAdminEndpointsRequireAdminToken(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := LoadAdminToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Fatalf("管理员令牌长度 = %d，期望 64（32 字节 hex）", len(tok))
	}

	svc := NewService(st, ServerSettings{}, nil)
	svc.AdminToken = tok
	svc.Mon = NewMonitor(filepath.Join(dir, "rec"), filepath.Join(dir, "access.log"), nil)
	h := svc.Handler()

	for _, path := range []string{"/api/v1/admin/overview", "/api/v1/admin/events", "/api/v1/admin/top"} {
		// 不带令牌
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s 无令牌时应 401，实际 %d", path, rec.Code)
		}
		// 错令牌
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Admin-Token", "deadbeef")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s 错令牌时应 401，实际 %d", path, rec.Code)
		}
		// 对令牌
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Admin-Token", tok)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 正确令牌时应 200，实际 %d（%s）", path, rec.Code, rec.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("%s 返回的不是合法 JSON：%v", path, err)
		}
	}
}

// loadAdminToken 在文件已被删除时会重新生成，这是轮换令牌的唯一手段。
func TestLoadAdminTokenRotates(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadAdminToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	same, err := LoadAdminToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != same {
		t.Fatal("已存在令牌时不该重新生成")
	}
	if err := os.Remove(filepath.Join(dir, AdminTokenFile)); err != nil {
		t.Fatal(err)
	}
	second, err := LoadAdminToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("删掉文件后应当生成新令牌")
	}
}
