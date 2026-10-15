package common

import (
	"encoding/json"
	"strings"
	"testing"
)

// 选线路的兜底行为是这套东西里最容易出错的地方：客户端本地存着一个 id，
// 而线路表由服务端随时可变。下面四种情况都必须能用，既不能报错，也不能连不上。
func TestChooseFallsBackSafely(t *testing.T) {
	coreParams := Params{
		Address: "proxy.example.com", Port: 443, SNI: "www.samsung.com",
		PublicKey: "PK-coreParams", ShortID: "SID-coreParams", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
	}
	edgeAParams := Params{
		Address: "203.0.113.7", Port: 443, SNI: "www.samsung.com",
		PublicKey: "PK-edgeAParams", ShortID: "SID-edgeAParams", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
		HysteriaSNI: "proxy.example.com",
	}
	r := &LoginResult{
		UUID:   "uuid-1",
		Params: coreParams,
		Instances: []Instance{
			{ID: "core", Name: "默认·总节点实例", Role: RoleExit, Params: coreParams},
			// 落地线路：服务端下发的就是 RoleExit、不带 Via（每条线路自己出网）。
			{ID: "edge-a", Name: "分支节点A测试实例", Role: RoleExit, Params: edgeAParams},
		},
	}

	got := r.Choose("edge-a")
	if got.Address != "203.0.113.7" || got.IsRelay() {
		t.Fatalf("选中分支节点A线路时参数不对: %+v", got)
	}
	// 落地线路不该带 via：带了就说明服务端又把它当成「第一跳」了，
	// 界面会跟着显示成「经中转出网」。
	if got.Via != "" {
		t.Fatalf("落地线路不该带 via（它自己就是出口）: %+v", got)
	}
	if got := r.Choose("edge-a"); got.HysteriaServerName() != "proxy.example.com" {
		t.Fatalf("落地线路的通道B 服务器名应为借来的证书域名，实际 %q", got.HysteriaServerName())
	}

	// 客户端存着一个服务端已经撤掉的 id：必须安静退回默认线路。
	if got := r.Choose("jp"); got.ID != "core" || got.Address != "proxy.example.com" {
		t.Fatalf("id 不存在时应退回默认线路，实际 %+v", got)
	}
	// 从未选过：取列表第一项（服务端把本机线路排在第一位）。
	if got := r.Choose(""); got.ID != "core" {
		t.Fatalf("id 为空时应取列表第一项，实际 %+v", got)
	}
	// 老服务端不下发线路表：行为必须与过去完全一致。
	old := &LoginResult{UUID: "uuid-1", Params: coreParams}
	if got := old.Choose("edge-a"); got.Address != coreParams.Address || got.ID != DefaultInstanceID {
		t.Fatalf("没有线路表时应合成默认线路，实际 %+v", got)
	}
}

// 落地线路的通道B 必须拿**证书上的域名**做 SNI，而不是它自己的地址。
//
// 这是最容易写错、且症状最难反推的一处：写错的现象只是「通道B 连不上」，
// 报错只会说证书校验失败。所以在这里钉死。
func TestHysteriaUsesCertDomainAsSNI(t *testing.T) {
	edgeAParams := Params{
		Address: "203.0.113.7", Port: 443, SNI: "www.samsung.com",
		PublicKey: "PK-edgeAParams", ShortID: "SID-edgeAParams", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
		HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "obfs-secret",
		HysteriaSNI: "proxy.example.com",
	}
	cfg := HysteriaConfig(FromParams(edgeAParams, "uuid-1", ProtoAuto, 17900, 17901), "alice", "pw")
	if !strings.Contains(cfg, "server: 203.0.113.7:8443") {
		t.Fatalf("hysteria 的 server 应当是落地节点自己的地址（证书是借来的，与它无关）:\n%s", cfg)
	}
	if !strings.Contains(cfg, "sni: proxy.example.com") {
		t.Fatalf("hysteria 的 sni 应当是证书域名（写错会导致证书校验失败）:\n%s", cfg)
	}

	// 直连线路没给 HysteriaSNI 时仍回退到 Address，保持旧行为不变。
	direct := Params{Address: "proxy.example.com", HysteriaEnabled: true, HysteriaPort: 8443, HysteriaObfs: "x"}
	if !strings.Contains(HysteriaConfig(FromParams(direct, "u", ProtoAuto, 1, 2), "a", "b"), "sni: proxy.example.com") {
		t.Fatal("没有 HysteriaSNI 时应回退用 Address")
	}
}

// 线路项的 JSON 必须与顶层 params 扁平同形 —— 客户端就是按这个形状解析的。
func TestInstanceJSONIsFlat(t *testing.T) {
	ins := Instance{
		ID: "edge-a", Name: "分支节点A测试实例", Role: RoleRelay, Via: "core",
		Params: Params{Address: "203.0.113.7", Port: 443, HysteriaSNI: "proxy.example.com"},
	}
	b, err := json.Marshal(ins)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "name", "role", "via", "address", "port", "hysteriaSNI"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("线路项 JSON 缺少扁平字段 %q: %s", k, b)
		}
	}
	if _, nested := m["Params"]; nested {
		t.Fatalf("Params 必须内嵌展平，不能是嵌套对象: %s", b)
	}
}
