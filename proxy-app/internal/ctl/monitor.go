package ctl

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 访问记录采集。
//
// 数据来源有两个，汇入同一套记录：
//   - 通道A：内核自己的访问日志。之所以能从日志里拿到「哪个账号访问了哪个域名」，
//     是因为日志行尾带 `email: <账号名>`——账号名在渲染配置时就写进了每个 VLESS
//     用户的 email 字段。不需要改内核，也不需要任何旁路抓包。
//   - 通道B：hysteria 统计数据接口的 /dump/streams。那条流量在 hysteria 进程里
//     就终止了，不经过内核，所以只能从 hysteria 自己那里取。见 monitor_hysteria.go。
//
// 必须清楚这类记录的边界：
//   - 拿到的是**目标主机名**（通道A 由 sniffing 从 TLS SNI / HTTP Host 得来，
//     通道B 是客户端请求的原始地址），不是完整 URL。HTTPS 的内容（含搜索关键词）
//     全程加密，记录里根本不存在。要拿到只能做中间人解密，
//     那会让 REALITY 的伪装彻底失效，得不偿失。
//   - 记录粒度是「连接/流」而不是「请求」：同一域名访问多次就是多条记录。
const (
	// accessPollEvery 是采集间隔。本地文件读取代价极低，间隔短一点监控页面
	// 才不至于显得迟钝；通道B 也复用这个间隔，而它的 /dump/streams 只返回
	// **当前活跃**的流，所以间隔越短漏掉的短连接越少。
	accessPollEvery = 2 * time.Second
	// accessRetainDays 是访问记录的保留天数，更早的按天文件会被删除。
	accessRetainDays = 14
	// accessMaxLogBytes 是内核访问日志的截断阈值。内核自己不轮转日志，
	// 一直追加下去会把磁盘占满，所以由我们定期清空。
	accessMaxLogBytes = 64 << 20
	// accessRecentKeep 是常驻内存的最近记录条数，供「最近访问」这类即时查询用。
	accessRecentKeep = 3000
	// hyStreamSeenMax 是「已采集过的流」键的容量上限。
	// 流结束后不会再出现，所以淘汰老键不会造成重复记录，但必须有上限，
	// 否则长时间运行下来这张表只增不减。
	hyStreamSeenMax = 20000
)

// AccessRecord 是一条访问记录。
//
// 字段名刻意取得很短：这些记录按天落盘，量级是每天几万条，
// 字段名在磁盘上要重复几万遍，省下来的都是白得的。
//
// 时间单位统一为 **Unix 微秒**。内核日志本身就带微秒，而毫秒不够用：
// 一次 DNS 突发会在同一毫秒里产生好几条一模一样的记录，按毫秒存下来之后
// 它们就无法区分，监控端做增量去重时会把真实记录当成重复丢掉
// （实测 611 条被并成 371 条）。微秒精度下这种碰撞基本不会发生。
type AccessRecord struct {
	// Time 是记录时间，Unix 微秒。
	Time int64 `json:"t"`
	// User 是账号名，来自内核日志行尾的 email，或 hysteria 的认证 id。
	User string `json:"u"`
	// Host 是目标主机名或 IP。命中 sniffing 时是域名，否则是 IP 字面量。
	Host string `json:"h"`
	Port int    `json:"p"`
	// Network 是 tcp 或 udp。udp 绝大多数是 DNS 查询。
	// 通道B 拿不到这个信息，留空。
	Network string `json:"n,omitempty"`
	// Outbound 是命中的出站：direct（直连）、block（拦截）等。
	// 通道B 没有这个概念，留空。
	Outbound string `json:"o,omitempty"`
	// Source 是客户端来源 IP，不带端口。通道B 的接口不返回它，留空。
	Source string `json:"s,omitempty"`
	// Channel 是这条记录来自哪条通道："B" 表示 hysteria。
	// **留空表示通道A**——磁盘上大量历史记录都没有这个字段，
	// 空值当作通道A 才能让新旧记录一致地显示。
	Channel string `json:"c,omitempty"`
}

// Monitor 持续把内核访问日志转成可查询的按天记录。
type Monitor struct {
	dir     string
	logPath string
	retain  time.Duration
	logf    func(string, ...any)

	// 通道B 的数据源（hysteria 的统计接口）。listen 为空表示未部署双通道，
	// 此时整套逻辑按单通道运行。
	hyListen string
	hySecret string
	hyClient *http.Client
	// hySeen 是已采集过的流，避免同一条流被反复记录。
	hySeen *streamSeen
	// hyWarnAt 用于抑制「连不上 hysteria 统计接口」这类重复日志。
	hyWarnAt time.Time

	mu     sync.RWMutex
	recent []AccessRecord
	// ingested 是本次进程运行期间写入的记录总数，供自检用。
	ingested int64
	// failed 是解析失败的行数。持续增长说明内核换了日志格式，应当告警。
	failed int64
}

// NewMonitor 构造采集器。dir 是记录落盘目录，logPath 是内核访问日志路径。
func NewMonitor(dir, logPath string, logf func(string, ...any)) *Monitor {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Monitor{
		dir: dir, logPath: logPath, retain: accessRetainDays * 24 * time.Hour,
		hyClient: &http.Client{Timeout: 5 * time.Second},
		hySeen:   newStreamSeen(hyStreamSeenMax),
		logf:     logf,
	}
}

// SetHysteria 让采集器顺带把通道B 的访问也收进来。
//
// listen 为空（未部署双通道）时什么都不做，调用方不必先判断。
func (m *Monitor) SetHysteria(listen, secret string) {
	m.hyListen, m.hySecret = listen, secret
}

// Stats 返回采集统计，供日志与自检使用。
func (m *Monitor) Stats() (ingested, failed int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ingested, m.failed
}

// Run 启动采集循环，直到 stop 关闭。
func (m *Monitor) Run(stop <-chan struct{}) {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		m.logf("创建访问记录目录失败: %v", err)
		return
	}
	m.cleanup()

	var offset int64
	var lastCleanup = time.Now()

	t := time.NewTicker(accessPollEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			offset = m.tailOnce(offset)
			// 通道B 另有一个数据源：它的流量不经过内核，得去 hysteria 那边取。
			m.collectHysteria()
			// 每天清一次过期记录就够了，没必要每 2 秒遍历目录。
			if time.Since(lastCleanup) > 24*time.Hour {
				m.cleanup()
				lastCleanup = time.Now()
			}
		}
	}
}

// tailOnce 从 offset 处读到文件末尾，返回新的偏移量。
//
// 只处理到最后一个换行符为止：内核可能正好写到一半，把半行读进来会解析失败，
// 留到下一轮再读即可（偏移量不推进，那半行会被重新读到完整）。
func (m *Monitor) tailOnce(offset int64) int64 {
	f, err := os.Open(m.logPath)
	if err != nil {
		// 日志文件还没被内核创建出来是正常情况（尚未有访问），不必报错。
		return offset
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return offset
	}
	size := fi.Size()
	// 文件比记录的偏移还小，说明被截断或轮转过，从头再来。
	if size < offset {
		offset = 0
	}
	if size == offset {
		return offset
	}

	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}
	buf := make([]byte, 1<<20)
	var pending []byte
	for {
		n, err := f.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	// 只取到最后一个换行，剩下的残行留待下轮。
	cut := lastIndexByte(pending, '\n')
	if cut < 0 {
		return offset
	}
	m.ingestBytes(pending[:cut+1])
	return offset + int64(cut+1)
}

func (m *Monitor) ingestBytes(b []byte) {
	var recs []AccessRecord
	var failed int64
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r, ok := ParseAccessLine(line)
		if ok {
			if isNoise(r) {
				continue
			}
			recs = append(recs, r)
			continue
		}
		// 只有「看起来是用户记录却解析不了」才算失败。
		// 控制面自己的 api 调用也在同一个日志里，它们本来就不该被解析成访问记录，
		// 一律计入失败的话这个指标会长期非零，失去告警意义。
		if strings.Contains(line, "email: ") {
			failed++
		}
	}
	if len(recs) == 0 {
		if failed > 0 {
			m.mu.Lock()
			m.failed += failed
			m.mu.Unlock()
		}
		return
	}
	m.mu.Lock()
	m.failed += failed
	m.mu.Unlock()
	if !m.ingestRecords(recs) {
		return
	}

	// 日志涨到阈值就清空。内核按追加方式写日志，清空后下一次写入从文件开头继续，
	// 不会留下空洞。
	if m.logSize() > accessMaxLogBytes {
		if err := os.Truncate(m.logPath, 0); err != nil {
			m.logf("截断内核访问日志失败: %v", err)
		}
	}
}

// ingestRecords 把一批记录落盘并放进内存最近列表。
//
// 两条通道共用这一条路径，保证「落盘 / 最近列表 / 计数」三者不会因为来源不同
// 而出现行为差异——否则很容易出现「某条通道的记录只在页面上看得到、重启就没了」
// 这类只在特定通道下复现的问题。返回 false 表示落盘失败。
func (m *Monitor) ingestRecords(recs []AccessRecord) bool {
	if len(recs) == 0 {
		return true
	}
	if err := m.writeRecords(recs); err != nil {
		m.logf("写入访问记录失败: %v", err)
		return false
	}
	m.mu.Lock()
	m.recent = append(m.recent, recs...)
	if n := len(m.recent) - accessRecentKeep; n > 0 {
		m.recent = append([]AccessRecord(nil), m.recent[n:]...)
	}
	m.ingested += int64(len(recs))
	m.mu.Unlock()
	return true
}

// isNoise 判断一条记录是否不含任何「访问了什么」的信息。
//
// 过滤明文 DNS（53）与加密 DNS（853，DNS over TLS / DNS over QUIC）。
// 这类记录里只有「查询发给了哪个解析器」（例如 1.1.1.1），没有「被查询的域名」——
// 无论通道A 的内核日志还是通道B 的 hysteria 接口，都不会解开 DNS 报文。
// 也就是说它回答不了任何监控问题，只会把记录条数撑大、让页面变得难读。
//
// 853 是后来补上的：手机把「私人 DNS」设成 1.1.1.1 时，会每半分钟向
// 1.1.1.1:853 建一条连接，于是页面上就整屏都是 1.1.1.1，
// 而它提供的信息量和 53 端口那条完全一样，同样该丢。
//
// 只过滤这两个端口而不是「所有 UDP/所有 IP 目标」：UDP 443（QUIC）是真实的站点访问，
// 必须保留；而用 IP 直连的站点（例如某个只有 IP 的服务）也是真实访问，不能一刀切。
// 通道B 拿不到传输层类型（Network 为空），所以对空值也按端口判断。
func isNoise(r AccessRecord) bool {
	switch r.Port {
	case 53, 853:
	default:
		return false
	}
	// 通道A 的 UDP 53 是明文 DNS，TCP 53 是 DNS over TCP；
	// 通道B 的（未知传输层）也一并按端口判断。三者都不含查询域名，注定过滤。
	return r.Network == "udp" || r.Network == "tcp" || r.Network == ""
}

func (m *Monitor) logSize() int64 {
	fi, err := os.Stat(m.logPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// writeRecords 按记录自身的日期分组追加到对应的按天文件。
// 用记录时间而不是当前时间来分组，跨零点读到的上一轮记录才会落到正确的文件里。
func (m *Monitor) writeRecords(recs []AccessRecord) error {
	// 目录在这里再确保一次，而不是只在 Run 里建：少了这句，「目录没建成」
	// 会让每条记录都静默写不进去，而监控页面只会显示成「没有访问」。
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	byDay := map[string][]AccessRecord{}
	for _, r := range recs {
		d := time.UnixMicro(r.Time).Format("2006-01-02")
		byDay[d] = append(byDay[d], r)
	}
	for day, group := range byDay {
		f, err := os.OpenFile(m.dayFile(day), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		w := bufio.NewWriter(f)
		for _, r := range group {
			b, err := json.Marshal(r)
			if err != nil {
				continue
			}
			w.Write(b)
			w.WriteByte('\n')
		}
		if err := w.Flush(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Monitor) dayFile(day string) string {
	return filepath.Join(m.dir, day+".jsonl")
}

// cleanup 删除保留期之外的按天文件。
func (m *Monitor) cleanup() {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-m.retain)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day, err := time.ParseInLocation("2006-01-02", strings.TrimSuffix(name, ".jsonl"), time.Local)
		if err != nil {
			continue
		}
		// 保留当天：cutoff 之前的整天文件才删。
		if day.Add(24 * time.Hour).Before(cutoff) {
			if err := os.Remove(filepath.Join(m.dir, name)); err == nil {
				m.logf("已删除过期访问记录 %s", name)
			}
		}
	}
}

// Recent 返回内存里最近 n 条记录，按时间升序。
func (m *Monitor) Recent(n int) []AccessRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n <= 0 || n > len(m.recent) {
		n = len(m.recent)
	}
	out := make([]AccessRecord, n)
	copy(out, m.recent[len(m.recent)-n:])
	return out
}

// Query 按时间与账号/主机过滤按天文件，返回**最新的** limit 条（按时间升序）。
// sinceUS 与记录时间一样是 Unix 微秒。
//
// 从最近一天往前读，攒够 limit 就停：这样既不会因为保留期长而把全部记录读进内存，
// 也保证返回的确实是最新的那批。
func (m *Monitor) Query(sinceUS int64, user, host string, limit int) ([]AccessRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	since := time.UnixMicro(sinceUS)
	var out []AccessRecord
	day := time.Now()
	first := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.Local)
	for ; !day.Before(first); day = day.AddDate(0, 0, -1) {
		recs, err := m.readDay(day.Format("2006-01-02"), sinceUS, user, host)
		if err != nil {
			// 当天文件不存在是正常的（那段时间没有访问）。
			if !os.IsNotExist(err) {
				return nil, err
			}
			continue
		}
		out = append(recs, out...)
		if len(out) >= limit {
			break
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time < out[j].Time })
	return out, nil
}

func (m *Monitor) readDay(day string, sinceUS int64, user, host string) ([]AccessRecord, error) {
	f, err := os.Open(m.dayFile(day))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []AccessRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r AccessRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		if r.Time < sinceUS {
			continue
		}
		if user != "" && r.User != user {
			continue
		}
		if host != "" && !strings.Contains(r.Host, host) {
			continue
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// ParseAccessLine 解析一行内核访问日志。
//
// 真实样本（注意 from 后面有时带 tcp: 前缀，括号里有时是 >> 有时是 ->）：
//
//	2026/09/19 04:11:19.362675 from 27.187.241.248:41478 accepted tcp:accounts.google.com:443 [reality-in >> direct] email: qichen
//	2026/09/19 04:11:23.365107 from tcp:27.187.241.248:41534 accepted udp:1.1.1.1:53 [reality-in >> direct] email: qichen
//
// 抽成独立函数是为了能用真实样本做单元测试：这段解析一旦写错，
// 表现是监控页面静默地什么都看不到，而不是报错。
func ParseAccessLine(line string) (AccessRecord, bool) {
	const emailMark = "email: "
	i := strings.LastIndex(line, emailMark)
	if i < 0 {
		// 没有 email 的行是控制面自身或未认证连接，不属于任何账号的访问。
		return AccessRecord{}, false
	}
	user := strings.TrimSpace(line[i+len(emailMark):])
	if user == "" || strings.ContainsAny(user, " \t") {
		return AccessRecord{}, false
	}
	head := line[:i]

	tsEnd := strings.Index(head, " from ")
	if tsEnd < 0 {
		return AccessRecord{}, false
	}
	ts, ok := parseAccessTime(head[:tsEnd])
	if !ok {
		return AccessRecord{}, false
	}

	rest := head[tsEnd+len(" from "):]
	accIdx := strings.Index(rest, " accepted ")
	if accIdx < 0 {
		return AccessRecord{}, false
	}
	source := stripHostPort(stripNetPrefix(strings.TrimSpace(rest[:accIdx])))
	rest = rest[accIdx+len(" accepted "):]

	// 目标后面跟着 [入站 >> 出站]；用最后一个 " [" 切，主机名里不会出现它。
	brIdx := strings.LastIndex(rest, " [")
	if brIdx < 0 {
		return AccessRecord{}, false
	}
	dest := strings.TrimSpace(rest[:brIdx])
	tags := strings.Trim(strings.TrimSpace(rest[brIdx+1:]), "[]")

	network, addr := splitNetPrefix(dest)
	host, port, ok := splitHostPort(addr)
	if !ok || host == "" {
		return AccessRecord{}, false
	}

	outbound := ""
	for _, sep := range []string{">>", "->"} {
		if p := strings.SplitN(tags, sep, 2); len(p) == 2 {
			outbound = strings.TrimSpace(p[1])
			break
		}
	}

	return AccessRecord{
		Time: ts, User: user, Host: host, Port: port,
		Network: network, Outbound: outbound, Source: source,
	}, true
}

// parseAccessTime 解析内核的时间戳前缀，例如 "2026/09/19 04:11:19.362675"，
// 返回 Unix 微秒。时间没有时区标记，按服务器本地时区解释。
func parseAccessTime(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		"2006/01/02 15:04:05.000000",
		"2006/01/02 15:04:05.000",
		"2006/01/02 15:04:05",
	} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.UnixMicro(), true
		}
	}
	return 0, false
}

// splitNetPrefix 拆出 "tcp" 与剩余部分；没有前缀时网络类型留空。
func splitNetPrefix(s string) (network, rest string) {
	for _, n := range []string{"tcp:", "udp:"} {
		if strings.HasPrefix(s, n) {
			return strings.TrimSuffix(n, ":"), s[len(n):]
		}
	}
	return "", s
}

func stripNetPrefix(s string) string {
	_, rest := splitNetPrefix(s)
	return rest
}

// splitHostPort 拆主机与端口。IPv6 是 [::1]:443 形式，所以从最后一个冒号切。
func splitHostPort(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, false
	}
	host := strings.Trim(s[:i], "[]")
	port, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

// stripHostPort 只保留主机部分（来源地址带端口，记录里不需要）。
func stripHostPort(s string) string {
	host, _, ok := splitHostPort(s)
	if !ok {
		return s
	}
	return host
}

// HostCount 是主机出现次数。
type HostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// Aggregate 统计时间窗内的访问分布。
//
// 与 Query 不同，这里流式读取、只保留计数，所以窗口开多长都不会把内存撑爆——
// 「最近 7 天访问最多的域名」这类查询必须走这条路径，用 Query 会把十万级记录读进内存。
func (m *Monitor) Aggregate(sinceUS int64, user string, top int) (hosts []HostCount, byUser map[string]int64, total int64, err error) {
	counts := map[string]int64{}
	byUser = map[string]int64{}
	since := time.UnixMicro(sinceUS)
	first := time.Date(since.Year(), since.Month(), since.Day(), 0, 0, 0, 0, time.Local)

	for day := time.Now(); !day.Before(first); day = day.AddDate(0, 0, -1) {
		f, oerr := os.Open(m.dayFile(day.Format("2006-01-02")))
		if oerr != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			var r AccessRecord
			if json.Unmarshal(sc.Bytes(), &r) != nil {
				continue
			}
			if r.Time < sinceUS {
				continue
			}
			if user != "" && r.User != user {
				continue
			}
			counts[r.Host]++
			byUser[r.User]++
			total++
		}
		serr := sc.Err()
		f.Close()
		if serr != nil {
			return nil, byUser, total, serr
		}
	}

	hosts = make([]HostCount, 0, len(counts))
	for h, c := range counts {
		hosts = append(hosts, HostCount{Host: h, Count: c})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Count != hosts[j].Count {
			return hosts[i].Count > hosts[j].Count
		}
		return hosts[i].Host < hosts[j].Host
	})
	if top > 0 && len(hosts) > top {
		hosts = hosts[:top]
	}
	return hosts, byUser, total, nil
}
