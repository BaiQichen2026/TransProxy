package ctl

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func writeNodesFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func reloadRegistry(t *testing.T, path string) *RelayRegistry {
	t.Helper()
	r, err := LoadRelayRegistry(path)
	if err != nil {
		t.Fatalf("读取登记表失败: %v", err)
	}
	return r
}

// 登记表不存在就是「单线路部署」，必须当成空表而不是错误 ——
// 否则给总节点升级时，光是多了这个功能就会让服务起不来。
func TestRelayRegistryMissingFileIsEmpty(t *testing.T) {
	r, err := LoadRelayRegistry(filepath.Join(t.TempDir(), "not-there.json"))
	if err != nil {
		t.Fatalf("文件不存在不该报错: %v", err)
	}
	if len(r.Snapshot()) != 0 {
		t.Fatalf("应为空表，实际 %v", r.Snapshot())
	}
	// 空表必须拒绝一切认证。
	if r.Authenticate("edge-a", "whatever") {
		t.Fatal("空表不该通过任何节点认证")
	}
}

func TestRelayRegistryAuthenticate(t *testing.T) {
	r := reloadRegistry(t, writeNodesFile(t, `{"nodes":[
	  {"id":"edge-a","name":"分支节点A测试实例","token":"tok-edgea"}
	]}`))
	if !r.Authenticate("edge-a", "tok-edgea") {
		t.Fatal("正确的 id + 口令应当通过")
	}
	for _, c := range [][2]string{
		{"edge-a", "tok-core"},  // 口令不对
		{"edge-a", "tok-u"},   // 前缀不算匹配
		{"jp", "tok-edgea"},  // id 不对
		{"", "tok-edgea"},    // 空 id
		{"edge-a", ""},        // 空口令
		{"edge-a", "tok-edgea "}, // 不 Trim 掉会误判，这里 Trim 后应通过（见下）
	} {
		got := r.Authenticate(c[0], c[1])
		want := c[0] == "edge-a" && c[1] == "tok-edgea "
		if got != want {
			t.Fatalf("Authenticate(%q,%q)=%v，期望 %v", c[0], c[1], got, want)
		}
	}
}

// 被攻陷的中转节点不能改掉自己的显示名，也不能换掉口令。
//
// 显示名会出现在用户的下拉框里，能改就意味着「冒充成别的线路」；
// 能换口令就意味着「泄漏之后永久有效、运维轮换不掉」。
func TestUpsertReportCannotChangeNameOrToken(t *testing.T) {
	path := writeNodesFile(t, `{"nodes":[
	  {"id":"edge-a","name":"分支节点A测试实例","token":"tok-edgea"}
	]}`)
	r := reloadRegistry(t, path)

	err := r.UpsertReport("edge-a", RelayNode{
		Name: "默认·总节点实例", Token: "tok-attacker", // 这两项必须被忽略
		Address: "203.0.113.7", Port: 443, SNI: "www.samsung.com",
		PublicKey: "PK-EDGEA", ShortID: "SID-EDGEA", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
	})
	if err != nil {
		t.Fatalf("上报应当成功: %v", err)
	}

	got := reloadRegistry(t, path).Snapshot()[0]
	if got.Name != "分支节点A测试实例" || got.Token != "tok-edgea" {
		t.Fatalf("名称与口令只能由本机配置决定，实际 name=%q token=%q", got.Name, got.Token)
	}
	if got.Address != "203.0.113.7" || got.PublicKey != "PK-EDGEA" || got.RegisteredAt == 0 {
		t.Fatalf("上报的入口参数应当被收下，实际 %+v", got)
	}
	// 未登记的 id 一律拒绝。
	if err := r.UpsertReport("jp", RelayNode{Address: "1.2.3.4"}); err == nil {
		t.Fatal("未登记的节点 id 必须拒绝")
	}
}

func testSettings(t *testing.T) ServerSettings {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ServerSettings{
		Domain: "proxy.example.com", ListenPort: 443, SNI: "www.samsung.com",
		Fingerprint: "chrome", Flow: "xtls-rprx-vision",
		PrivateKey:      base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		ShortID:         "0011223344556677",
		HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "obfs-secret",
		NodeID: "core", NodeName: "默认·总节点实例",
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	st, err := LoadStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("建账号库失败: %v", err)
	}
	return NewService(st, testSettings(t), nil)
}

// 线路表的组装规则：本机排第一；落地线路的通道B 参数复用本机那份（端口/混淆口令
// 必须一致），但 SNI 必须换成出口域名；参数没上报全的节点先不出现。
//
// 另一件同样重要的事：落地线路的 role 必须是 **exit**、且不带 via。这里以前是
// relay + via=core，客户端会把它显示成「入口 203.0.113.8 · 经中转出网」——
// 那是已废弃的「中转到总节点」方案的措辞，会把用户绕回去。
func TestInstancesLocalFirstAndNodeLineIsItsOwnExit(t *testing.T) {
	s := newTestService(t)
	s.Relays = &RelayRegistry{Nodes: []RelayNode{
		{ID: "edge-a", Name: "分支节点A测试实例", Token: "t",
			Address: "203.0.113.7", Port: 443, SNI: "www.samsung.com",
			PublicKey: "PK-EDGEA", ShortID: "SID-EDGEA", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
			RegisteredAt: 1},
		{ID: "jp", Name: "还没上报的节点", Token: "t2"}, // 参数不全 → 不能下发
	}}

	// 授权前：只剩本地线路。
	only, err := s.Instances(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 || only[0].ID != "core" {
		t.Fatalf("没被授权时不该下发任何落地线路，实际 %+v", only)
	}

	list, err := s.Instances([]string{"edge-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("应当只有「本机 + 已上报的节点」两条，实际 %d 条: %+v", len(list), list)
	}
	if list[0].ID != "core" || list[0].Name != "默认·总节点实例" || list[0].Role != roleExit {
		t.Fatalf("第一条必须是本机线路: %+v", list[0])
	}
	if list[0].Address != "proxy.example.com" {
		t.Fatalf("本机线路的地址应为域名: %+v", list[0])
	}

	edgeA := list[1]
	if edgeA.ID != "edge-a" || edgeA.Role != roleExit || edgeA.Via != "" {
		t.Fatalf("落地线路必须是自己出网（role=exit、不带 via），实际 %+v", edgeA)
	}
	if edgeA.Address != "203.0.113.7" || edgeA.PublicKey != "PK-EDGEA" {
		t.Fatalf("落地线路应当用节点上报的入口参数: %+v", edgeA)
	}
	if edgeA.HysteriaSNI != "proxy.example.com" {
		t.Fatalf("落地线路的通道B 必须用出口域名做 SNI（分支节点A借的是总节点的证书），实际 %q", edgeA.HysteriaSNI)
	}
	if edgeA.HysteriaPort != 8443 || edgeA.HysteriaObfs != "obfs-secret" {
		t.Fatalf("落地线路的通道B 端口与混淆口令应复用本机那份: %+v", edgeA)
	}
}

func nodeUsersReq(id, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/node/users", nil)
	if id != "" {
		r.Header.Set("X-Node-Id", id)
	}
	if token != "" {
		r.Header.Set("X-Node-Token", token)
	}
	return r
}

// 账号列表接口：没认证一律 401；只给最小集；revision 在账号集合不变时必须稳定
// （否则中继节点每轮都会重载内核，把走中转线路的用户反复踢下线）。
func TestNodeUsers(t *testing.T) {
	s := newTestService(t)
	s.Relays = &RelayRegistry{Nodes: []RelayNode{{ID: "edge-a", Name: "分支节点A", Token: "tok-edgea"}}}
	if _, err := s.Store.Add("alice", "pw-alice-1", "", 0); err != nil {
		t.Fatal(err)
	}
	// 授权是必须的：默认谁都不能用中转线路。
	grantNode(t, s, "alice", []string{"edge-a"})

	rec := httptest.NewRecorder()
	s.handleNodeUsers(rec, nodeUsersReq("", ""))
	if rec.Code != 401 {
		t.Fatalf("没带凭据应当 401，实际 %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.handleNodeUsers(rec, nodeUsersReq("edge-a", "tok-wrong"))
	if rec.Code != 401 {
		t.Fatalf("口令不对应当 401，实际 %d", rec.Code)
	}

	fetch := func() (string, []nodeUser) {
		rec := httptest.NewRecorder()
		s.handleNodeUsers(rec, nodeUsersReq("edge-a", "tok-edgea"))
		if rec.Code != 200 {
			t.Fatalf("认证通过应当 200，实际 %d：%s", rec.Code, rec.Body.String())
		}
		var out struct {
			Revision string     `json:"revision"`
			Users    []nodeUser `json:"users"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("返回不是合法 JSON: %v", err)
		}
		return out.Revision, out.Users
	}

	rev1, users := fetch()
	if len(users) != 1 || users[0].Name != "alice" || users[0].UUID == "" {
		t.Fatalf("列表内容不对: %+v", users)
	}
	// 只给最小集：不能把密码哈希之类的东西带出去。
	//
	// 凭据确实要下发，但走的是**另一个接口**（/node/hashes，见 TestNodeHashes）。
	// 混在这里的话，一个只跑通道A 的节点也会顺手拿到一堆密码哈希。
	probe := httptest.NewRecorder()
	s.handleNodeUsers(probe, nodeUsersReq("edge-a", "tok-edgea"))
	for _, leak := range []string{"password", "hash", "quota", "note", "PassEnc", "$2"} {
		if strings.Contains(probe.Body.String(), leak) {
			t.Fatalf("账号接口不该带出 %q 这类字段: %s", leak, probe.Body.String())
		}
	}

	if rev2, _ := fetch(); rev2 != rev1 {
		t.Fatalf("账号集合没变时 revision 必须稳定：%s -> %s", rev1, rev2)
	}

	// 新账号**没被授权**：既不该出现在列表里，也不该改变 revision
	// （否则每加一个用不上中转的人，都会让节点白重载一次内核、踢掉在线用户）。
	if _, err := s.Store.Add("bob", "pw-bob-1", "", 0); err != nil {
		t.Fatal(err)
	}
	rev3, users3 := fetch()
	if len(users3) != 1 || rev3 != rev1 {
		t.Fatalf("没授权的账号不该下发、也不该改 revision：rev %s->%s users=%+v", rev1, rev3, users3)
	}

	// 授权之后才出现，且 revision 必须变（节点据此重载内核、把新身份装进去）。
	grantNode(t, s, "bob", []string{"edge-a"})
	rev4, users4 := fetch()
	if len(users4) != 2 || rev4 == rev3 {
		t.Fatalf("授权后应出现且 revision 要变：rev %s->%s users=%+v", rev3, rev4, users4)
	}

	// 收回授权：立刻从列表里消失（节点下次轮询就会把他从内核摘掉）。
	grantNode(t, s, "bob", nil)
	if _, users5 := fetch(); len(users5) != 1 {
		t.Fatalf("收回授权后不该再出现，实际 %+v", users5)
	}

	// 停用的账号同样不给。
	grantNode(t, s, "bob", []string{"edge-a"})
	if err := s.Store.Modify("bob", func(u *User) { u.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if _, users6 := fetch(); len(users6) != 1 {
		t.Fatalf("停用账号不该下发，实际 %+v", users6)
	}
}

// 通道B 的凭据接口。
//
// 它给出的东西是这个系统里最敏感的一类：bcrypt 哈希可以离线爆破，而用户往往
// 在别处复用同一个密码。所以这里的边界要一条条钉住：未认证不给、只给被授权且
// 启用的账号、下发的必须是能真正校验原密码的哈希。
//
// 另见 TestNodeUsers 里那条「/node/users 不该带出哈希」—— 凭据走单独接口，
// 是为了让只跑通道A 的节点根本拿不到它。
func TestNodeHashes(t *testing.T) {
	s := newTestService(t)
	s.Relays = &RelayRegistry{Nodes: []RelayNode{{ID: "edge-a", Name: "分支节点A", Token: "tok-edgea"}}}
	if _, err := s.Store.Add("alice", "pw-alice-1", "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Add("bob", "pw-bob-1", "", 0); err != nil {
		t.Fatal(err)
	}
	grantNode(t, s, "alice", []string{"edge-a"}) // 只有 alice 被授权用分支节点A

	fetch := func(id, token string) (int, []NodeHash) {
		rec := httptest.NewRecorder()
		s.handleNodeHashes(rec, nodeUsersReq(id, token))
		var out struct {
			Users []NodeHash `json:"users"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Users
	}

	// 节点口令不对：401，且响应里不能有任何哈希。
	code, _ := fetch("edge-a", "tok-wrong")
	if code != 401 {
		t.Fatalf("口令不对应当 401，实际 %d", code)
	}
	if code, _ := fetch("jp", "tok-edgea"); code != 401 {
		t.Fatalf("未登记的节点 id 应当 401，实际 %d", code)
	}

	code, users := fetch("edge-a", "tok-edgea")
	if code != 200 || len(users) != 1 || users[0].Name != "alice" {
		t.Fatalf("只该给出被授权的 alice，实际 %d %+v", code, users)
	}
	// 必须是真 bcrypt 哈希，且能校验出原密码 —— 分支节点A那边就靠它决定放不放行。
	// 给错东西的症状是「通道B 全体认证失败」，在这台机器上完全看不出来。
	if err := bcrypt.CompareHashAndPassword([]byte(users[0].Hash), []byte("pw-alice-1")); err != nil {
		t.Fatalf("下发的哈希无法校验出原密码: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(users[0].Hash), []byte("pw-wrong")); err == nil {
		t.Fatal("哈希不该能校验出错误的密码")
	}

	// 停用之后立刻从名单里消失（下一轮节点就会把人挡在门外）。
	if err := s.Store.Modify("alice", func(u *User) { u.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if _, users := fetch("edge-a", "tok-edgea"); len(users) != 0 {
		t.Fatalf("停用账号不该下发凭据，实际 %+v", users)
	}
}

// grantNode 直接改账号库里的线路授权，等价于管理员在面板上操作。
func grantNode(t *testing.T, s *Service, name string, nodes []string) {
	t.Helper()
	if err := s.Store.Modify(name, func(u *User) { u.AllowNodes = nodes }); err != nil {
		t.Fatal(err)
	}
}

// 上报来自另一台机器，**一律按不可信输入处理**：只认「存在、启用、被授权用这个节点」
// 的账号，负数与天文数字都要夹住，没授权的账号绝不能借此被虚增用量。
func TestNodeReportValidatesUntrustedInput(t *testing.T) {
	s := newTestService(t)
	s.Relays = &RelayRegistry{Nodes: []RelayNode{{ID: "edge-a", Name: "分支节点A", Token: "tok-edgea"}}}
	if _, err := s.Store.Add("alice", "pw-alice-1", "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Add("bob", "pw-bob-1", "", 0); err != nil {
		t.Fatal(err)
	}
	grantNode(t, s, "alice", []string{"edge-a"}) // 只有 alice 被授权用分支节点A

	post := func(id, token, payload string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/node/report", strings.NewReader(payload))
		r.Header.Set("X-Node-Id", id)
		r.Header.Set("X-Node-Token", token)
		rec := httptest.NewRecorder()
		s.handleNodeReport(rec, r)
		return rec
	}

	if rec := post("edge-a", "wrong", `{"stats":[]}`); rec.Code != 401 {
		t.Fatalf("口令不对应当 401，实际 %d", rec.Code)
	}
	if rec := post("jp", "tok-edgea", `{"stats":[]}`); rec.Code != 401 {
		t.Fatalf("未登记的节点 id 应当 401，实际 %d", rec.Code)
	}

	// 四种情况混在一起：正常、未授权、不存在、负数。
	body := `{"stats":[
	  {"name":"alice","up":100,"down":200},
	  {"name":"bob","up":999,"down":999},
	  {"name":"nobody","up":500,"down":0},
	  {"name":"alice","up":-100,"down":-1}
	],"access":["2026/09/23 10:00:00 alice accepted tcp:example.com:443 [relay-in -> direct]"]}`
	if rec := post("edge-a", "tok-edgea", body); rec.Code != 200 {
		t.Fatalf("正常上报应当 200，实际 %d：%s", rec.Code, rec.Body.String())
	}

	if a, _ := s.Store.Snapshot("alice"); a.UsedBytes != 300 {
		t.Fatalf("alice 应只累加 100+200=300（负数不计），实际 %d", a.UsedBytes)
	}
	if b, _ := s.Store.Snapshot("bob"); b.UsedBytes != 0 {
		t.Fatalf("未被授权用分支节点A的 bob 不该被记账，实际 %d", b.UsedBytes)
	}
}

func TestClampDelta(t *testing.T) {
	for _, c := range []struct{ in, want int64 }{
		{-5, 0}, {0, 0}, {1234, 1234}, {maxNodeReportBytes + 1, maxNodeReportBytes},
	} {
		if got := clampDelta(c.in); got != c.want {
			t.Fatalf("clampDelta(%d)=%d，期望 %d", c.in, got, c.want)
		}
	}
}

// 落地节点报上来的速率：按两轮上报的间隔折算；节点掉线后必须归零，
// 不能一直显示掉线前的旧速率。
func TestRemoteRateLifecycle(t *testing.T) {
	s := newTestService(t)

	// 第一次上报没有间隔可比：只更新累计，不编造速率。
	s.noteRemoteStat("alice", 300, 600)
	if got := s.remoteRateFor("alice"); got.Up != 0 || got.Down != 0 {
		t.Fatalf("第一次上报不该产生速率，实际 %+v", got)
	}

	// 把上一次的时间往前推 30 秒，再报同样的增量 → 速率应为 10 / 20 B/s。
	s.remoteMu.Lock()
	s.remoteAt = time.Now().Add(-30 * time.Second)
	s.remoteMu.Unlock()
	s.noteRemoteStat("alice", 300, 600)
	got := s.remoteRateFor("alice")
	if got.Up != 10 || got.Down != 20 {
		t.Fatalf("速率应按 30 秒间隔折算成 10/20，实际 %+v", got)
	}

	// 超过有效期没再上报 → 归零（节点掉线了）。
	s.remoteMu.Lock()
	s.remoteAt = time.Now().Add(-2 * remoteRateTTL)
	s.remoteMu.Unlock()
	if got := s.remoteRateFor("alice"); got.Up != 0 || got.Down != 0 {
		t.Fatalf("掉线后速率应归零，实际 %+v", got)
	}
}

// 授权值的校验：写错的 id 必须直接报错。
//
// 不校验的话，把 edge-a 打成 edge-ax 不会报任何错，只会静默变成「授了权但用不了」，
// 在管理界面上完全看不出来。
func TestNormalizeAllowNodes(t *testing.T) {
	r := &RelayRegistry{Nodes: []RelayNode{{ID: "edge-a"}, {ID: "jp"}}}
	got, err := r.NormalizeAllowNodes([]string{" edge-a ", "edge-a", "jp", ""})
	if err != nil {
		t.Fatalf("合法输入不该报错: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"edge-a", "jp"}) {
		t.Fatalf("应当去空、Trim、去重并保序，实际 %v", got)
	}
	if _, err := r.NormalizeAllowNodes([]string{"usa"}); err == nil {
		t.Fatal("未知线路 id 必须报错")
	}
	if _, err := r.NormalizeAllowNodes(nil); err != nil {
		t.Fatalf("空列表表示取消全部授权，不该报错: %v", err)
	}
	// 本机一条中转线路都没登记时，任何授权都无意义。
	if _, err := (&RelayRegistry{}).NormalizeAllowNodes([]string{"edge-a"}); err == nil {
		t.Fatal("没有任何已登记线路时应报错")
	}
}
