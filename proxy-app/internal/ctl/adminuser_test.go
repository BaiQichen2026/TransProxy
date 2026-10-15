package ctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newAdminService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := LoadAdminToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(st, ServerSettings{}, nil)
	svc.AdminToken = tok
	return svc, tok
}

func postAdmin(t *testing.T, svc *Service, token, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Admin-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	return rec
}

// 账号名会被拼进临时文件路径（AddUserRuntime 写 /tmp/transctl-adu-<名字>.json），
// 所以名字必须严格限字符。这条测试防的是「用 ../ 之类的名字写到任意路径」。
func TestAdminUserCreateRejectsBadNames(t *testing.T) {
	svc, tok := newAdminService(t)

	bad := []struct {
		name string
		body string
	}{
		{"路径穿越", `{"name":"../../etc/cron.d/pwn","password":"pw123456"}`},
		{"含斜杠", `{"name":"a/b","password":"pw123456"}`},
		{"含空格", `{"name":"a b","password":"pw123456"}`},
		{"含点", `{"name":"a.b","password":"pw123456"}`},
		{"空名字", `{"name":"","password":"pw123456"}`},
		{"超长", `{"name":"` + strings.Repeat("a", 33) + `","password":"pw123456"}`},
		{"中文", `{"name":"账号一","password":"pw123456"}`},
		{"负额度", `{"name":"ok","password":"pw123456","quotaBytes":-1}`},
		{"密码过短", `{"name":"ok","password":"123"}`},
		{"不是 JSON", `{`},
	}
	for _, c := range bad {
		rec := postAdmin(t, svc, tok, "/api/v1/admin/user/create", c.body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s（%s）应返回 400，实际 %d：%s", c.name, c.body, rec.Code, rec.Body.String())
		}
	}
	// 一个都不该落库
	if got := len(svc.Store.List()); got != 0 {
		t.Fatalf("非法请求不该创建账号，实际有 %d 个", got)
	}
}

func TestAdminUserEndpointsRequireToken(t *testing.T) {
	svc, _ := newAdminService(t)
	for _, p := range []string{
		"/api/v1/admin/user/create",
		"/api/v1/admin/user/update",
		"/api/v1/admin/user/delete",
	} {
		rec := postAdmin(t, svc, "", p, `{"name":"a"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s 无令牌应 401，实际 %d", p, rec.Code)
		}
		rec = postAdmin(t, svc, "wrong", p, `{"name":"a"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s 错令牌应 401，实际 %d", p, rec.Code)
		}
	}
}

func TestAdminUserUpdateAndDeleteNeedExistingUser(t *testing.T) {
	svc, tok := newAdminService(t)
	rec := postAdmin(t, svc, tok, "/api/v1/admin/user/update", `{"name":"nobody","note":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("改不存在账号应 404，实际 %d", rec.Code)
	}
	rec = postAdmin(t, svc, tok, "/api/v1/admin/user/delete", `{"name":"nobody"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("删不存在账号应 404，实际 %d", rec.Code)
	}
	// 没给任何要改的字段
	if _, err := svc.Store.Add("alice", "pw123456", "", 0); err != nil {
		t.Fatal(err)
	}
	rec = postAdmin(t, svc, tok, "/api/v1/admin/user/update", `{"name":"alice"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("没给字段应 400，实际 %d", rec.Code)
	}
}

// 网页改账号与命令行改账号是两个进程写同一个文件。
// 不重新加载的话，网页侧会用陈旧的内存副本把命令行刚加的账号抹掉。
func TestModifyDoesNotClobberExternalChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	daemon, err := LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.Add("alice", "pw123456", "", 0); err != nil {
		t.Fatal(err)
	}

	// 模拟另一个进程（transctl 命令行）也在同一个文件上加账号
	cli, err := LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Add("bob", "pw123456", "", 0); err != nil {
		t.Fatal(err)
	}

	// 服务侧（内存里还不知道 bob）改 alice 的备注
	if err := daemon.Modify("alice", func(u *User) { u.Note = "改过的备注" }); err != nil {
		t.Fatal(err)
	}

	fresh, err := LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, u := range fresh.List() {
		names[u.Name] = u.Note
	}
	if _, ok := names["bob"]; !ok {
		t.Fatal("命令行加的账号被服务侧覆盖掉了")
	}
	if names["alice"] != "改过的备注" {
		t.Fatalf("alice 的备注没落盘：%q", names["alice"])
	}
}

// 删除账号必须连 UUID 一起消失，避免留下「库里没有、内核里还能连」的幽灵用户。
func TestRemovePurgesUser(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.Add("alice", "pw123456", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if u.UUID == "" {
		t.Fatal("新账号应当有 UUID")
	}
	if err := st.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Snapshot("alice"); ok {
		t.Fatal("删除后仍能查到账号")
	}
	if err := st.Remove("alice"); err == nil {
		t.Fatal("重复删除应当报错")
	}
}

// 改密码必须换 UUID，否则旧密码期间发出去的连接参数在本次内核运行期内仍然可用。
func TestSetPasswordRotatesUUID(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := st.Add("alice", "pw123456", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	oldUUID := before.UUID
	if err := st.SetPassword("alice", "newpw123456"); err != nil {
		t.Fatal(err)
	}
	after, _ := st.Snapshot("alice")
	if after.UUID == oldUUID {
		t.Fatal("改密码后 UUID 没有更换")
	}
	if !after.CheckPassword("newpw123456") {
		t.Fatal("新密码校验失败")
	}
	if after.CheckPassword("pw123456") {
		t.Fatal("旧密码仍然可用")
	}
}

// 账号列表接口要带上管理界面需要的字段。
func TestAdminOverviewCarriesUserFields(t *testing.T) {
	svc, tok := newAdminService(t)
	if _, err := svc.Store.Add("alice", "pw123456", "测试备注", 1024); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/overview", nil)
	req.Header.Set("X-Admin-Token", tok)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("overview 应 200，实际 %d", rec.Code)
	}
	var v struct {
		Users []struct {
			Name       string `json:"name"`
			Note       string `json:"note"`
			Enabled    bool   `json:"enabled"`
			QuotaBytes int64  `json:"quotaBytes"`
		} `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Users) != 1 || v.Users[0].Name != "alice" || v.Users[0].Note != "测试备注" ||
		!v.Users[0].Enabled || v.Users[0].QuotaBytes != 1024 {
		t.Fatalf("账号字段不完整：%+v", v.Users)
	}
}
