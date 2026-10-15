//go:build windows

package ctl

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"transproxy/internal/common"
)

// 服务端与客户端各自定义了一份「线路项」的 wire 类型：internal/common 是 Windows
// 专属包（直接 import golang.org/x/sys/windows），服务端在 Linux 上编译不了它，
// 所以两边没法共用同一个类型（原因见 nodes.go）。
//
// 这个测试就是两者之间的契约：字段名、是否内嵌展平、字段增减，任何一边改了另一边
// 没跟上，都在这里失败 —— 而不是等到用户装上客户端才发现「选了线路连不上」。
//
// 只在 Windows 上跑，因为要 import common。
func TestNodeInstanceMatchesClientWireFormat(t *testing.T) {
	srv := NodeInstance{
		ID: "edge-a", Name: "分支节点A测试实例", Role: roleRelay, Via: "core",
		Params: Params{
			Address: "203.0.113.7", Port: 443, SNI: "www.samsung.com",
			PublicKey: "pk", ShortID: "sid", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
			HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "obfs",
			HysteriaSNI: "proxy.example.com",
		},
	}
	cli := common.Instance{
		ID: "edge-a", Name: "分支节点A测试实例", Role: common.RoleRelay, Via: "core",
		Params: common.Params{
			Address: "203.0.113.7", Port: 443, SNI: "www.samsung.com",
			PublicKey: "pk", ShortID: "sid", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
			HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "obfs",
			HysteriaSNI: "proxy.example.com",
		},
	}

	if a, b := flatKeys(t, srv), flatKeys(t, cli); !reflect.DeepEqual(a, b) {
		t.Fatalf("服务端与客户端的线路项字段不一致:\n服务端 %v\n客户端 %v", a, b)
	}
	if roleExit != common.RoleExit || roleRelay != common.RoleRelay {
		t.Fatalf("角色取值不一致: 服务端 %q/%q，客户端 %q/%q",
			roleExit, roleRelay, common.RoleExit, common.RoleRelay)
	}

	// 更强的检查：服务端真实序列化的结果，必须能被客户端类型完整解出来，且值不丢。
	raw, err := json.Marshal(srv)
	if err != nil {
		t.Fatal(err)
	}
	var back common.Instance
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("客户端解不出服务端下发的线路项: %v（%s）", err, raw)
	}
	if back.ID != "edge-a" || back.Role != common.RoleRelay || back.Via != "core" ||
		back.Address != "203.0.113.7" || back.HysteriaSNI != "proxy.example.com" ||
		back.HysteriaPort != 8443 || !back.IsRelay() {
		t.Fatalf("字段值在传输中丢失了: %+v（%s）", back, raw)
	}
}

// flatKeys 返回序列化后的顶层字段名（升序），用来比对两边的 wire 形状。
func flatKeys(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
