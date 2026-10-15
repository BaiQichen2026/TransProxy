package ctl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 认证路径必须看到「磁盘上的最新账号」，而不是本进程上次轮询时的内存副本。
//
// 管理命令（transctl useradd/passwd/del）是与控制服务完全独立的进程，
// 它们只改文件；控制服务的内存副本要靠 syncFromDisk 主动比对文件签名才会更新。
// 早先 Snapshot 没做这一步，于是「命令行刚加好的账号，登录报账号或密码错误，
// 等几秒（下一次流量轮询）又好了」——认证结果被后台轮询的时机左右，
// 这种不确定性在认证路径上是不能接受的。
func TestSnapshotSeesExternalChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	st, err := LoadStore(path)
	if err != nil {
		t.Fatalf("初始化账号库失败：%v", err)
	}
	if _, ok := st.Snapshot("external"); ok {
		t.Fatal("账号还不存在，不应该查到")
	}

	// 模拟另一个进程（管理命令）往同一份文件里加了一个账号。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取账号库失败：%v", err)
	}
	var onDisk Store
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("解析账号库失败：%v", err)
	}
	onDisk.Users = append(onDisk.Users, &User{
		Name:     "external",
		Password: "irrelevant",
		UUID:     NewUUID(),
		Enabled:  true,
	})
	b, err := json.MarshalIndent(&onDisk, "", "  ")
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("写回账号库失败：%v", err)
	}

	u, ok := st.Snapshot("external")
	if !ok {
		t.Fatal("外部进程刚加的账号，Snapshot 却查不到——认证会用着一份过期的内存副本")
	}
	if u.Name != "external" {
		t.Fatalf("查到的账号不对：%q", u.Name)
	}

	// Find 走的是同一份内存副本，也必须同步，否则「存不存在」的判断会和 Snapshot 打架。
	if st.Find("external") == nil {
		t.Fatal("外部进程刚加的账号，Find 却查不到")
	}
}

// 删除也必须立刻对认证路径可见：否则被删掉的账号在下次轮询之前还能登录。
func TestSnapshotSeesExternalDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	st, err := LoadStore(path)
	if err != nil {
		t.Fatalf("初始化账号库失败：%v", err)
	}
	if _, err := st.Add("doomed", "password123", "", 0); err != nil {
		t.Fatalf("建账号失败：%v", err)
	}
	if _, ok := st.Snapshot("doomed"); !ok {
		t.Fatal("刚建的账号应当能查到")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取账号库失败：%v", err)
	}
	var onDisk Store
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("解析账号库失败：%v", err)
	}
	onDisk.Users = nil
	b, err := json.MarshalIndent(&onDisk, "", "  ")
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("写回账号库失败：%v", err)
	}

	if _, ok := st.Snapshot("doomed"); ok {
		t.Fatal("账号已被外部进程删除，Snapshot 仍能查到——被删的账号还能继续登录")
	}
}
