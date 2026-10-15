package ctl

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// 落地节点（分支节点A）的内核与 hysteria 配置渲染。
//
// 【它与出口节点（总节点）的关系只有控制面】
// 数据面分支节点A**自己出网**：通道A 走 freedom 出站（见 RenderRelayConfig 的 outbounds），
// 通道B 由本机 hysteria 终结后直接出网（见 RenderHysteriaConfig）。用户要的就是
// 「从分支节点A的 IP 访问互联网」，两条通道都不经过任何上游中转。
//
// 分支节点A主动连总节点只做三件事，全在控制面：
//  1. 上报自身（入口地址/公钥/shortId），供出口下发给客户端；
//  2. 拉授权账号的 UUID，用来渲染通道A 的入站；
//  3. 拉授权账号的密码哈希，用来在本机校验通道B 的认证（只在提供通道B 时）。
//
// 【为什么必须开统计与访问日志】
// 出口在这台，总节点那边看不到这些字节，所以「每个账号用了多少」「访问了哪些域名」
// 只能在本地记，再由 transrelay 报回出口汇总。本机的管理接口一律只听 127.0.0.1。

// RelaySettings 是落地节点自己的配置（relay.json，0600）。
//
// 名字里的 relay 是历史遗留：早先的设计是「中转到出口」，那一套已废弃
// （现在每个实例都自己出网）。改名会牵动配置文件、systemd 单元与二进制名，
// 而收益只有「名字更准」，所以留着 —— 与文档文件名里的「中转」同一个理由。
type RelaySettings struct {
	// NodeID / Token 是它向出口节点认证自己的凭据，必须与出口节点 nodes.json
	// 里那条登记项的 id / token 完全一致。
	NodeID string `json:"nodeId"`
	Token  string `json:"token"`

	// ControlURL 是出口节点控制面的基地址，例如 https://proxy.example.com:8443
	ControlURL string `json:"controlUrl"`

	// ListenPort 是本机对客户端暴露的 REALITY 端口。
	ListenPort int `json:"listenPort"`
	// Advertise 是本机向出口节点上报的「客户端该连哪个地址」。
	// 一般写本机公网 IP：出口节点无法可靠地替我们推断它。
	Advertise string `json:"advertise"`

	// DecoySNI / DecoyTarget 是 REALITY 借用的伪装站点，两端必须一致。
	DecoySNI    string `json:"decoySni"`
	DecoyTarget string `json:"decoyTarget"`
	// Flow / Fingerprint 是上报给出口节点、再由出口节点转给客户端的参数。
	// Flow 必须与出口节点入站接受的一致，否则客户端连不上。
	Flow        string `json:"flow"`
	Fingerprint string `json:"fingerprint"`

	// ConfigPath 是内核配置落盘位置；IdentityPath 是本机 REALITY 身份的落盘位置。
	ConfigPath   string `json:"configPath"`
	IdentityPath string `json:"identityPath"`
	// XrayUnit 是要重载的 systemd 单元名（账号集合变化时重启它）。
	XrayUnit string `json:"xrayUnit"`
	// XrayBin 是内核二进制路径，用来在替换线上配置前先校验一遍（见 cmd/transrelay）。
	XrayBin string `json:"xrayBin"`
	// APIPort 是本机内核统计/管理 API 的端口，**只监听 127.0.0.1**。
	// 出口在这台，按用户记账只能自己做，所以必须开。
	APIPort int `json:"apiPort"`
	// AccessLog 是访问记录落盘位置，用来回答「谁访问了哪些域名」。
	AccessLog string `json:"accessLog"`
	// HysteriaStatsListen / HysteriaStatsSecret 是本机 hysteria2 的流量统计接口。
	// 通道B 由本机的 hysteria 终结并直接出网，内核看不到这些字节，
	// 所以要从 hysteria 自己那里取。留空表示本节点不提供通道B。
	HysteriaStatsListen string `json:"hysteriaStatsListen"`
	HysteriaStatsSecret string `json:"hysteriaStatsSecret"`

	// ---------- 通道B（hysteria2）----------
	//
	// 这几项只在「本节点也提供通道B」时有意义，开关就是 HysteriaListenPort：
	// 为 0 表示本节点只提供通道A。这时不仅不起 hysteria，也**不会**
	// 去出口节点领密码哈希（见 cmd/transrelay）—— 用不上就不该拿。
	//
	// 端口与混淆口令必须与出口节点一致：客户端手上的通道B 参数是出口下发的，
	// 里面写的就是出口那一套，分支节点A这边只有用同一套才连得上。
	HysteriaListenPort int    `json:"hysteriaListenPort"`
	HysteriaObfs       string `json:"hysteriaObfs"`
	// HysteriaCert / HysteriaKey 是**出口节点的证书**（部署时拷过来）。
	// 客户端用出口域名做 SNI，证书对不上必然连不上；而分支节点A没有自己的域名。
	HysteriaCert string `json:"hysteriaCert"`
	HysteriaKey  string `json:"hysteriaKey"`
	// HysteriaAuthListen 是本机认证回调的监听地址，**只监听回环**：
	// 它只由本机 hysteria 调用，对外毫无用处，暴露出去就等于开放一个
	// 不需要令牌、每次请求触发一次 bcrypt 比较的口令校验接口。
	HysteriaAuthListen string `json:"hysteriaAuthListen"`
	// HysteriaMasquerade 是通道B 的伪装目标，与出口节点保持一致。
	HysteriaMasquerade string `json:"hysteriaMasquerade"`
	// HysteriaConfigPath / HysteriaUnit 是 hysteria 的配置落盘位置与 systemd 单元名。
	HysteriaConfigPath string `json:"hysteriaConfigPath"`
	HysteriaUnit       string `json:"hysteriaUnit"`
}

// HysteriaAuthPath 是认证回调的路径。
//
// 渲染配置（RenderHysteriaConfig）与起监听（cmd/transrelay）两端都要用同一个值：
// 写错任何一处，现象都只是「通道B 全体认证失败」，很难反推到是路径不一致。
const HysteriaAuthPath = "/api/v1/hysteria/auth"

// HysteriaEnabled 报告本节点是否提供通道B。
//
// 以端口为准：其余字段少填哪一个都渲染不出能用的配置（RenderHysteriaConfig 会报错），
// 索性只认这一个开关，部署时少一个「以为开了其实没开」的坑。
func (rs RelaySettings) HysteriaEnabled() bool { return rs.HysteriaListenPort > 0 }

// LoadRelaySettings 读取中转节点配置。
func LoadRelaySettings(path string) (RelaySettings, error) {
	var rs RelaySettings
	b, err := os.ReadFile(path)
	if err != nil {
		return rs, err
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		return rs, fmt.Errorf("中转配置不是合法 JSON: %w", err)
	}
	if rs.NodeID == "" || rs.Token == "" || rs.ControlURL == "" {
		return rs, fmt.Errorf("中转配置缺少 nodeId / token / controlUrl")
	}
	// Advertise 必须显式配：它是「客户端该连哪个地址」，出口节点替我们猜不出来。
	// 少了它不会报错，只会表现为「客户端下拉框里一直没有这条线路」，
	// 那种问题在远端机器上很难查。所以宁可启动即失败。
	if rs.Advertise == "" {
		return rs, fmt.Errorf("中转配置缺少 advertise（对客户端公布的入口地址，一般填本机公网 IP）")
	}
	if rs.ListenPort == 0 {
		rs.ListenPort = 443
	}
	return rs.withDefaults(), nil
}

// withDefaults 补齐缺省值。
//
// LoadRelaySettings 与 RenderRelayConfig **都**要走它：渲染入口也补一次，
// 万一有人绕过配置加载直接构造 RelaySettings，也不会渲染出 "access": ""
// 这种让内核起不来的配置（这个坑是测试先踩出来的）。
func (rs RelaySettings) withDefaults() RelaySettings {
	if rs.ListenPort == 0 {
		rs.ListenPort = 443
	}
	if rs.ConfigPath == "" {
		rs.ConfigPath = "/usr/local/etc/xray/config.json"
	}
	if rs.IdentityPath == "" {
		rs.IdentityPath = "/usr/local/etc/transrelay/identity.json"
	}
	if rs.XrayUnit == "" {
		rs.XrayUnit = "xray"
	}
	if rs.XrayBin == "" {
		rs.XrayBin = "/usr/local/bin/xray"
	}
	if rs.APIPort == 0 {
		// 出口节点用 10085，这里错开一个，避免以后两台机器被混着配置时撞端口。
		rs.APIPort = 10086
	}
	if rs.AccessLog == "" {
		rs.AccessLog = "/var/log/xray/access.log"
	}
	if rs.Flow == "" {
		rs.Flow = "xtls-rprx-vision"
	}
	if rs.Fingerprint == "" {
		rs.Fingerprint = "chrome"
	}
	if rs.HysteriaConfigPath == "" {
		rs.HysteriaConfigPath = "/etc/hysteria/config.yaml"
	}
	if rs.HysteriaUnit == "" {
		// 官方安装脚本生成的单元名，换个名字只会让「重启失败」变成一个难查的问题。
		rs.HysteriaUnit = "hysteria-server"
	}
	if rs.HysteriaAuthListen == "" {
		// 与出口节点的 10086（内核 API）错开，免得两台机器被混着配置时撞端口。
		rs.HysteriaAuthListen = "127.0.0.1:10087"
	}
	if rs.HysteriaMasquerade == "" {
		rs.HysteriaMasquerade = "https://www.samsung.com/"
	}
	return rs
}

// RelayIdentity 是这个中转节点自己的 REALITY 身份。
//
// 与出口节点同规矩：私钥不写进代码、也不写进任何配置文件，首次运行随机生成后
// 落盘 0600。它与 shortId 合起来就是这个节点的身份，谁拿到谁就能冒充它、
// 把客户端流量终结在自己手里。
type RelayIdentity struct {
	PrivateKey string `json:"privateKey"`
	ShortID    string `json:"shortId"`
}

// LoadOrCreateRelayIdentity 读取身份，不存在则生成一份并落盘。
func LoadOrCreateRelayIdentity(path string) (RelayIdentity, error) {
	var id RelayIdentity
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &id); err != nil {
			return id, fmt.Errorf("本机身份文件不是合法 JSON: %w", err)
		}
		if id.PrivateKey != "" && id.ShortID != "" {
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return id, err
	}

	// 复用出口节点那套生成逻辑，保证两边的密钥格式、长度完全一致。
	s := ServerSettings{}
	if err := ensureNodeIdentity(&s); err != nil {
		return id, err
	}
	id = RelayIdentity{PrivateKey: s.PrivateKey, ShortID: s.ShortID}
	out, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return id, err
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return id, err
	}
	return id, os.WriteFile(path, out, 0o600)
}

// PublicKey 由本机私钥推导出 REALITY 公钥（上报给出口节点、再转给客户端）。
func (id RelayIdentity) PublicKey() (string, error) {
	return publicKeyOf(id.PrivateKey)
}

// RelayUser 是出口节点发来的账号，只含渲染内核配置所必需的最小集。
type RelayUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// RenderRelayConfig 生成落地节点的内核配置。
//
// users 是「被授权使用本节点」的账号：只有它们能通过入站认证。
// 名单由出口节点下发（见 cmd/transrelay 的心跳），分支节点A本地不存账号库。
func RenderRelayConfig(rs RelaySettings, id RelayIdentity, users []RelayUser) ([]byte, error) {
	rs = rs.withDefaults()
	// 排序后再渲染：账号集合没变时输出必须逐字节一致，否则节点每轮都会
	// 认为「配置变了」→ 白重载一次内核 → 踢掉正在用这条线路的人。
	sorted := make([]RelayUser, 0, len(users))
	for _, u := range users {
		if u.Name == "" || u.UUID == "" {
			continue
		}
		sorted = append(sorted, u)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	clients := make([]any, 0, len(sorted))
	for _, u := range sorted {
		clients = append(clients, map[string]any{
			"id": u.UUID, "flow": rs.Flow, "email": u.Name,
		})
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": rs.AccessLog},
		// 统计与 API 服务：出口在这台，按用户记账只能自己做。
		"api":   map[string]any{"tag": "api", "services": []string{"StatsService", "HandlerService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{
				"statsUserUplink": true, "statsUserDownlink": true,
			}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds": []any{
			// 只监听 127.0.0.1：这是本机的管理接口，不对外。
			map[string]any{
				"tag": "api", "listen": "127.0.0.1", "port": rs.APIPort,
				"protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1"},
			},
			map[string]any{
				"tag": relayInboundTag, "listen": "0.0.0.0", "port": rs.ListenPort,
				"protocol": "vless",
				"settings": map[string]any{"clients": clients, "decryption": "none"},
				"streamSettings": map[string]any{
					"network": "tcp", "security": "reality",
					"realitySettings": map[string]any{
						"show": false, "target": rs.DecoyTarget, "xver": 0,
						"serverNames": []string{rs.DecoySNI},
						"privateKey":  id.PrivateKey,
						"shortIds":    []string{id.ShortID},
					},
				},
				// 入站嗅探保留：Vision 需要它拿到目标域名才能正常工作，
				// 访问记录里的域名也靠它。
				"sniffing": map[string]any{
					"enabled": true, "destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		// 【顺序在这里是有语义的】Xray 拿**第一个**出站当默认路由，而落地节点的
		// 默认路由必须就是出网 —— 它只有这一条路径，不存在「从别的路径悄悄出去」
		// 这回事。所以 direct 必须排第一。
		//
		// 曾经把 block 排在第一（照抄出口节点「fail-closed」的思路），后果是
		// **所有用户流量都被黑洞掉**：真机验证时 access.log 里是
		//   accepted tcp:api.ipify.org:443 [relay-in >> block] email: qichen
		// 客户端表现为 TLS 握手失败，而两台服务器上都不报任何错。
		// 那个思路只适用于「每个用户一条出站、路由按 user 匹配」的形态 ——
		// 那里默认路由兜到 block，才不会把流量算到别人头上。
		"outbounds": []any{
			// UseIPv4：代理出去的域名只解析到 IPv4，与分支节点A出口保持一致，
			// 不让这条链路承载 IPv6。
			map[string]any{"tag": "direct", "protocol": "freedom",
				"settings": map[string]any{"domainStrategy": "UseIPv4"}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
			map[string]any{"tag": "api", "protocol": "freedom"},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []any{"api"}, "outboundTag": "api"},
			// 只拦明确要拦的（BT），不许把它理解成「默认全拦」。
			map[string]any{"type": "field", "protocol": []any{"bittorrent"}, "outboundTag": "block"},
		}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// relayInboundTag 是中转节点入站的标签，用于把「所有从客户端进来的流量」
// 都按用户路由到各自的出站上。
const relayInboundTag = "relay-in"

// RenderHysteriaConfig 生成落地节点的 hysteria 服务端配置。
//
// 【为什么认证走 HTTP 回调，而不是把账号写进这份配置（userpass）】
// 账号密码是 bcrypt 哈希。写进配置意味着「配置被读走 = 全站哈希泄漏」，
// 而这份配置文件是要跟随部署、会被备份、也可能被误拷的。改成回调之后：
//
//   - 哈希只留在 transrelay 进程的内存里（见 cmd/transrelay/hysteriaauth.go），
//     不落盘、不进配置、不写日志；
//   - 账号集合变化只要换内存里那张表，**不必重写配置、更不必重启 hysteria** ——
//     重启会把正在用通道B 的人全部踢下线。
//
// 代价是「本机的 transrelay 必须活着」：它挂了通道B 就没人能认证。
// 这个代价是明确接受的 —— 它同时也负责给客户端下发线路，本来就是个必需进程。
func RenderHysteriaConfig(rs RelaySettings) ([]byte, error) {
	rs = rs.withDefaults()
	if !rs.HysteriaEnabled() {
		return nil, fmt.Errorf("未配置 hysteriaListenPort，本节点不提供通道B")
	}
	// 这三项少任何一个都渲染不出能用的配置，且症状都是「客户端连不上」——
	// 与其让它安静地生成一份错配置，不如直接拒绝。
	if rs.HysteriaCert == "" || rs.HysteriaKey == "" {
		return nil, fmt.Errorf("缺少 hysteriaCert / hysteriaKey：分支节点A没有自己的域名，必须借用出口节点的证书")
	}
	if rs.HysteriaObfs == "" {
		return nil, fmt.Errorf("缺少 hysteriaObfs：混淆口令必须与出口节点一致，否则客户端连不上")
	}
	if rs.HysteriaStatsListen == "" || rs.HysteriaStatsSecret == "" {
		return nil, fmt.Errorf("缺少 hysteriaStatsListen / hysteriaStatsSecret：出口在这台，按账号记账只能自己做")
	}

	authURL := "http://" + rs.HysteriaAuthListen + HysteriaAuthPath
	return []byte(fmt.Sprintf(`listen: :%d
tls:
  cert: %s
  key: %s
obfs:
  type: salamander
  salamander:
    password: %s
auth:
  type: http
  http:
    url: %s
trafficStats:
  listen: %s
  secret: %s
masquerade:
  type: proxy
  proxy:
    url: %s
    rewriteHost: true
`,
		rs.HysteriaListenPort, rs.HysteriaCert, rs.HysteriaKey, rs.HysteriaObfs,
		authURL, rs.HysteriaStatsListen, rs.HysteriaStatsSecret, rs.HysteriaMasquerade)), nil
}
