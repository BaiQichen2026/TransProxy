package main

// 上报：把本机（落地节点）的每用户流量与访问记录报给出口节点。
//
// 为什么必须报：出口在本机，出口节点那边完全看不到这些字节 ——
// 不报的话监控面板上走这条线路的账号永远是零，额度也管不了。
//
// 报的是**增量**：内核计数是「开机以来累计」（内核一重载就归零），
// 累计值对出口没有意义，由出口自己累加才不会因为重载而跳变。

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"transproxy/internal/ctl"
)

// statsState 记住上一轮的原始计数与日志偏移，用来算增量。
type statsState struct {
	xray     map[string]ctl.TrafficPair
	accessAt int64
}

// collect 采集本轮要上报的增量。
//
// 任何一项取不到都只是这一项不报，绝不因此让同步（乃至连接）失败 ——
// 面板的数字晚一轮补上就行。
func (a *agent) collect() ([]ctl.NodeStat, []string) {
	stats := []ctl.NodeStat{}

	// 通道A：内核按用户统计（配置里 policy.levels 已打开）。
	if cur, err := ctl.QueryTraffic(a.rs.APIPort, 5*time.Second); err == nil {
		for name, now := range cur {
			up, down := delta(a.stat.xray[name].Up, now.Up), delta(a.stat.xray[name].Down, now.Down)
			if up > 0 || down > 0 {
				stats = append(stats, ctl.NodeStat{Name: name, Up: up, Down: down})
			}
		}
		a.stat.xray = cur
	} else {
		a.logf("读取内核流量失败（本轮不报通道A）: %v", err)
	}

	// 通道B：hysteria 由本机终结并直接出网，内核看不到这些字节，
	// 只能从 hysteria 自己的统计接口取 —— 那个接口是「读后清零」，拿到的天然是增量。
	if a.rs.HysteriaStatsListen != "" {
		if hy, err := ctl.QueryHysteriaTraffic(a.rs.HysteriaStatsListen, a.rs.HysteriaStatsSecret, 5*time.Second); err == nil {
			for name, d := range hy {
				if d.Up > 0 || d.Down > 0 {
					stats = append(stats, ctl.NodeStat{Name: name, Up: d.Up, Down: d.Down})
				}
			}
		} else {
			a.logf("读取 hysteria 流量失败（本轮不报通道B）: %v", err)
		}
	}

	lines, off := readAccess(a.rs.AccessLog, a.stat.accessAt)
	a.stat.accessAt = off
	return stats, lines
}

// delta 算增量。新值比旧值小说明内核重载过（计数从零起算），这时整段新值都是增量。
func delta(prev, now int64) int64 {
	if now <= prev {
		if now > 0 && now < prev {
			return now
		}
		return 0
	}
	return now - prev
}

// readAccess 读出访问日志里自上次以来新增的完整行，并返回新的偏移。
//
// 只处理**完整的行**：末尾那段可能正被内核写着，留到下一轮，否则会报出半行、
// 让出口那边的解析器把一条记录拆成两条错误记录。
func readAccess(path string, off int64) ([]string, int64) {
	if path == "" {
		return nil, off
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, off
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, off
	}
	if fi.Size() < off {
		// 日志被轮转或清空过，从头读。
		off = 0
	}
	if fi.Size() == off {
		return nil, off
	}
	size := fi.Size() - off
	if size > maxAccessBytes {
		// 落后太多（比如日志被清过又猛涨）：只取最后一段。
		// 丢掉的部分在日志里已经不可追，宁可少报也不要把内存吃光。
		skip := size - maxAccessBytes
		off += skip
		size = maxAccessBytes
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, off
	}
	buf = buf[:n]
	idx := bytes.LastIndexByte(buf, '\n')
	if idx < 0 {
		return nil, off // 一行都还没写完
	}
	newOff := off + int64(idx) + 1

	lines := []string{}
	for _, ln := range strings.Split(string(buf[:idx]), "\n") {
		if ln = strings.TrimRight(ln, "\r"); ln != "" {
			lines = append(lines, ln)
		}
	}
	// 行数超限时只留最近的：最重要的是别让一条上报把请求体撑爆。
	if len(lines) > maxAccessLines {
		lines = lines[len(lines)-maxAccessLines:]
	}
	return lines, newOff
}

// report 把本轮的流量与访问记录报给出口节点。
//
// 报失败只记日志、不影响连接：连接是否可用不依赖上报，下一轮补上即可。
func (a *agent) report() {
	stats, access := a.collect()
	if len(stats) == 0 && len(access) == 0 {
		return
	}
	body, err := json.Marshal(map[string]any{"stats": stats, "access": access})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, a.rs.ControlURL+"/api/v1/node/report", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Id", a.rs.NodeID)
	req.Header.Set("X-Node-Token", a.rs.Token)
	var out struct{}
	if err := a.do(req, &out); err != nil {
		a.logf("上报失败（下一轮重试）: %v", err)
		return
	}
	a.logf("已上报：%d 个账号的流量、%d 条访问记录", len(stats), len(access))
}
