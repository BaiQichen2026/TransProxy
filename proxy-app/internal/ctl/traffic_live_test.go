package ctl

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 通道B 的上下行方向必须映射正确，否则监控面板会把上传和下载显示反。
//
// hysteria 的文档注释是按「服务端 → 代理目标」的口径写的，很容易读反；
// 真正的依据在它的 server/copy.go：client→target 那一段计入 Tx，
// target→client 那一段计入 Rx。所以 Tx 是用户上行、Rx 是用户下行，
// 与内核对 uplink/downlink 的口径（同样站在用户视角）一致。
func TestQueryHysteriaTrafficSplitsUpDown(t *testing.T) {
	var sawClear, sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawClear = r.URL.Query().Get("clear")
		sawAuth = r.Header.Get("Authorization")
		// 顺带带上一个空账号名：hysteria 在没有用户时可能回这个，必须丢掉。
		_, _ = io.WriteString(w, `{"alice":{"tx":100,"rx":4000},"":{"tx":7,"rx":7}}`)
	}))
	defer srv.Close()

	got, err := QueryHysteriaTraffic(strings.TrimPrefix(srv.URL, "http://"), "sekrit", 3*time.Second)
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if sawClear != "1" {
		t.Error("没有带 clear=1：接口读后不清零，同一批流量会在下次采集时被重复计入")
	}
	if sawAuth != "sekrit" {
		t.Errorf("鉴权头不对：%q", sawAuth)
	}
	if len(got) != 1 {
		t.Fatalf("空账号名应被丢弃，实际拿到 %d 个：%+v", len(got), got)
	}
	a := got["alice"]
	if a.Up != 100 || a.Down != 4000 {
		t.Fatalf("上下行映射反了：期望 上行=100 下行=4000，实际 %+v", a)
	}
}

// 没配密钥或地址时不应发请求，否则会拿空 secret 去撞接口。
func TestQueryHysteriaTrafficDisabled(t *testing.T) {
	for _, c := range []struct{ listen, secret string }{
		{"", "s"}, {"127.0.0.1:9999", ""},
	} {
		got, err := QueryHysteriaTraffic(c.listen, c.secret, time.Second)
		if err != nil || got != nil {
			t.Fatalf("listen=%q secret=%q 应当直接返回空，实际 %v / %v", c.listen, c.secret, got, err)
		}
	}
}

// 监控面板的「实时速率」全靠这两个字段，字段名或语义一变面板就白屏。
func TestAdminOverviewExposesLiveSpeed(t *testing.T) {
	svc, tok := newAdminService(t)
	if _, err := svc.Store.Add("alice", "pw12345678", "", 0); err != nil {
		t.Fatal(err)
	}

	svc.liveMu.Lock()
	svc.live["alice"] = liveStat{UpSpeed: 1234, DownSpeed: 5678, SessionUp: 11, SessionDown: 22}
	svc.liveMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview", nil)
	req.Header.Set("X-Admin-Token", tok)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d：%s", rec.Code, rec.Body.String())
	}
	var body struct {
		SpeedAt int64 `json:"speedAt"`
		Users   []struct {
			Name        string `json:"name"`
			UpSpeed     int64  `json:"upSpeed"`
			DownSpeed   int64  `json:"downSpeed"`
			SessionUp   int64  `json:"sessionUp"`
			SessionDown int64  `json:"sessionDown"`
		} `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("返回体不是预期的 JSON：%v", err)
	}
	if len(body.Users) != 1 {
		t.Fatalf("应当只有 alice 一个账号，实际 %d 个", len(body.Users))
	}
	u := body.Users[0]
	if u.UpSpeed != 1234 || u.DownSpeed != 5678 || u.SessionUp != 11 || u.SessionDown != 22 {
		t.Fatalf("速率/会话字段没有透出：%+v", u)
	}
}

// 没有任何采集数据时不能报错或者 panic：新装的节点、控制面刚起来都会走到这里。
func TestAdminOverviewWithoutLiveData(t *testing.T) {
	svc, tok := newAdminService(t)
	if _, err := svc.Store.Add("bob", "pw12345678", "", 0); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview", nil)
	req.Header.Set("X-Admin-Token", tok)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d：%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"upSpeed":0`) {
		t.Fatalf("缺少 upSpeed 字段（哪怕是 0）：%s", rec.Body.String())
	}
}
