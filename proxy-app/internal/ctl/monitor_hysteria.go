package ctl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// 通道B（Hysteria2）的访问记录采集。
//
// 为什么不能像通道A 那样读日志：通道B 的流量在 hysteria 进程里就终止了，
// 根本不经过内核，内核的访问日志里没有它。
//
// 数据来源是 hysteria 的统计数据接口 `/dump/streams`——就是我们在用来算流量的
// 那个接口所在的同一个监听端口，所以**不需要改 hysteria 的任何配置**。
// 它返回当前活跃流的信息，其中 `req_addr` 就是客户端请求的目标地址，
// 正是「谁访问了什么」需要的那个字段。
//
// 与通道A 相比，这里有两个固有局限，界面上也应当体现出差异：
//
//  1. **它是快照，不是日志**。接口只返回「当前还在活跃」的流，所以一条
//     建立又关闭都发生在两次轮询之间的短连接会被漏掉。轮询间隔沿用
//     accessPollEvery（2 秒），配合下面的去重表，绝大多数连接都能抓到，
//     但无法保证 100%。
//  2. **拿不到传输层类型与出站标签**。记录里的 Network/Outbound/Source 留空。
//     因此 DNS 噪声只能按端口（53）判断。
type hyStream struct {
	Auth       string `json:"auth"`
	Connection uint32 `json:"connection"`
	Stream     uint64 `json:"stream"`
	ReqAddr    string `json:"req_addr"`
	// InitialAt 是流的建立时间，用它而不是轮询时刻：否则同一条流在几秒后
	// 才被采集到时，记录时间会偏晚，看起来像是「访问发生在采集那一刻」。
	InitialAt string `json:"initial_at"`
}

// collectHysteria 拉一次通道B 的活跃流并入库。listen 未配置时直接返回。
func (m *Monitor) collectHysteria() {
	if m.hyListen == "" {
		return
	}
	recs, err := m.fetchHysteriaStreams()
	if err != nil {
		// 抑制重复日志：hysteria 没跑或正在重启时这个接口会连不上，
		// 每 2 秒打一行会把日志刷得没法看。
		if time.Since(m.hyWarnAt) > 5*time.Minute {
			m.logf("通道B 访问采集失败（将重试）：%v", err)
			m.hyWarnAt = time.Now()
		}
		return
	}
	m.ingestRecords(recs)
}

func (m *Monitor) fetchHysteriaStreams() ([]AccessRecord, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+m.hyListen+"/dump/streams", nil)
	if err != nil {
		return nil, err
	}
	if m.hySecret != "" {
		req.Header.Set("Authorization", m.hySecret)
	}
	resp, err := m.hyClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("统计接口返回 %d", resp.StatusCode)
	}
	var payload struct {
		Streams []hyStream `json:"streams"`
	}
	// 用 LimitReader 兜底：这个接口的响应大小取决于活跃连接数，
	// 被异常流量撑大时不该把控制面的内存拖下去。
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&payload); err != nil {
		return nil, err
	}

	now := time.Now().UnixMicro()
	var out []AccessRecord
	for _, st := range payload.Streams {
		// 去重键用 connection+stream：它们在 hysteria 内部唯一，且同一条流
		// 会在连续多次轮询里反复出现。
		key := fmt.Sprintf("%s|%d|%d", st.Auth, st.Connection, st.Stream)
		if m.hySeen.has(key) {
			continue
		}
		if st.Auth == "" || st.ReqAddr == "" {
			// 目标地址尚未确定（还在连接中）。这里刻意**不登记**，
			// 下一轮拿到地址时再收——登记了就永久丢掉这条流。
			continue
		}
		host, port, ok := splitHostPort(st.ReqAddr)
		if !ok || host == "" {
			continue
		}
		ts := parseRFC3339Micro(st.InitialAt)
		if ts == 0 {
			ts = now
		}
		r := AccessRecord{
			Time: ts, User: st.Auth, Host: host, Port: port,
			Channel: "B",
		}
		// 每个键只登记一次（add 对已存在的键会直接返回 false，不会重复入队），
		// 所以噪声也一并登记，免得每轮重复判断。
		m.hySeen.add(key)
		if isNoise(r) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// parseRFC3339Micro 解析 hysteria 返回的 RFC3339Nano 时间戳，返回 Unix 微秒。
func parseRFC3339Micro(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0
	}
	return t.UnixMicro()
}

// streamSeen 是「已经采集过的流」集合，带容量上限。
//
// 流结束后不会再出现在接口返回里，所以淘汰最老的键不会造成重复记录；
// 但上限是必须的，否则长时间运行后这张表只增不减。
type streamSeen struct {
	m     map[string]struct{}
	queue []string
	head  int
	max   int
}

func newStreamSeen(max int) *streamSeen {
	return &streamSeen{m: make(map[string]struct{}, max), max: max}
}

// add 登记一个键，返回 true 表示此前没见过。对已存在的键直接返回，
// 不会重复入队，因此调用方不必担心同一键被反复登记。
func (s *streamSeen) add(key string) bool {
	if _, ok := s.m[key]; ok {
		return false
	}
	s.m[key] = struct{}{}
	s.queue = append(s.queue, key)
	if len(s.queue)-s.head > s.max {
		delete(s.m, s.queue[s.head])
		s.head++
		// 定期压实底层数组，否则 queue 会随着 head 前进而无限增长。
		if s.head > 4096 && s.head*2 > len(s.queue) {
			s.queue = append([]string(nil), s.queue[s.head:]...)
			s.head = 0
		}
	}
	return true
}

func (s *streamSeen) has(key string) bool {
	_, ok := s.m[key]
	return ok
}
