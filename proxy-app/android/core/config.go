package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

// 分流模式，取值与 Windows 端一致。
const (
	ModeSmart  = "smart"
	ModeGlobal = "global"
)

// 传输通道，取值与 Windows 端一致。
const (
	// ProtoReality 是通道A：内核直接建 VLESS + REALITY 隧道，最隐蔽。
	ProtoReality = "reality"
	// ProtoHysteria 是通道B：内核把流量交给旁边的 hysteria 客户端（在 Android 上是
	// 本进程内的库，在 Windows 上是旁挂进程），抗丢包更好。
	ProtoHysteria = "hysteria"
)

// Params 是 Kotlin 侧交过来的连接参数。字段名与服务端下发的一致，
// 免得中间再翻译一层、翻译错了还很难发现。
type Params struct {
	Address     string `json:"address"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Flow        string `json:"flow"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
	SpiderX     string `json:"spiderX"`
	Mode        string `json:"mode"`

	// SocksPort 是本机调试用 SOCKS 入站端口，0 表示不开启。
	// 它默认只监听 127.0.0.1：留着它就能绕开 VPN 单独验证隧道本身是否通，
	// 出问题时可以快速区分「隧道坏了」和「VPN 接管坏了」。
	SocksPort int `json:"socksPort"`

	// AllowLAN 为真时该 SOCKS 入站绑到 0.0.0.0，同一局域网内的其它设备
	// 可以用「手机 IP + 端口」借这条隧道上网。
	// 入站是无认证的，只在可信网络里开启。
	AllowLAN bool `json:"allowLan"`

	// Protocol 选择走哪条通道：reality（默认）或 hysteria。
	Protocol string `json:"protocol"`

	// 通道B（Hysteria2）的参数，由服务端随登录响应下发。
	HysteriaEnabled bool   `json:"hysteriaEnabled"`
	HysteriaPort    int    `json:"hysteriaPort"`
	HysteriaObfs    string `json:"hysteriaObfs"`
	// HysteriaSocksPort 是本机 hysteria 客户端监听的 SOCKS 端口，
	// 内核的 proxy 出站会指向它。0 表示用默认端口。
	HysteriaSocksPort int `json:"hysteriaSocksPort"`
	// HyAuth 是「账号:密码」，hysteria 的认证凭据。
	//
	// 与其它字段不同，这一项**不应该落盘**：只有通道B才需要它，
	// 而它等同于账号密码明文。落盘策略见 TransVpnService：
	// 用户没勾「记住密码」时，写盘前会被剔除。
	HyAuth string `json:"hyAuth,omitempty"`

	// LogLevel 控制内核日志级别，空表示 warning。
	// 排查「流量有没有进隧道」时设为 info，界面就能看到每条连接的出站归属。
	LogLevel string `json:"logLevel"`
}

// logLevel 返回内核日志级别，取值只允许 warning / info / debug。
// 不认识的值一律退回 warning：写错一个级别把日志刷爆，比不写日志更麻烦。
func (p Params) logLevel() string {
	switch p.LogLevel {
	case "info", "debug":
		return p.LogLevel
	default:
		return "warning"
	}
}

const (
	// tunMTU 1400：移动网络的稳妥值，与 Windows 端保持一致。
	// 调大会在部分链路上被分片，调小则降低吞吐。
	tunMTU = 1400
	// tunName 只是给内核内部分配用的名字，Android 侧网卡名由 VpnService 决定。
	tunName = "xray0"
)

// BuildConfig 把连接参数展开成完整的内核配置。
//
// 之所以把配置生成也放在这里而不是 Kotlin：分流规则是安全相关的部分
// （决定了哪些流量不走代理），只应该有一份实现，且与 Windows 端语义一致。
func BuildConfig(paramsJSON string) (string, error) {
	var p Params
	if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
		return "", fmt.Errorf("解析连接参数失败：%w", err)
	}
	if err := p.validate(); err != nil {
		return "", err
	}
	if p.SpiderX == "" {
		p.SpiderX = "/"
	}
	if p.Fingerprint == "" {
		p.Fingerprint = "chrome"
	}
	if p.Mode == "" {
		p.Mode = ModeSmart
	}

	var b strings.Builder
	b.WriteString("{\n")
	// 默认 warning：正常连接不打日志，省得日志缓冲被刷爆、也省电。
	// 需要排查「流量到底有没有进隧道」时把它调成 info，界面上就能看到
	// 每条连接命中的出站（tun-in -> proxy / direct）。
	b.WriteString(fmt.Sprintf("  \"log\": { \"loglevel\": %q },\n", p.logLevel()))
	b.WriteString("  \"inbounds\": [\n")
	b.WriteString(tunInbound())
	if p.SocksPort > 0 {
		b.WriteString(",\n")
		listen := "127.0.0.1"
		if p.AllowLAN {
			listen = "0.0.0.0"
		}
		b.WriteString(socksInbound(p.SocksPort, listen))
	}
	b.WriteString("\n  ],\n")
	b.WriteString("  \"outbounds\": [\n")
	b.WriteString(proxyOutbound(p))
	b.WriteString(",\n")
	b.WriteString(`    { "tag": "direct", "protocol": "freedom" },` + "\n")
	b.WriteString(`    { "tag": "block", "protocol": "blackhole" }` + "\n")
	b.WriteString("  ],\n")
	b.WriteString(`  "routing": {` + "\n")
	// AsIs 而不是 IPIfNonMatch：后者会为了补足 IP 规则而用本地 DNS 解析域名，
	// 被墙域名在本地常被污染成国内 IP，反而命中 geoip:cn 被误判为直连。
	// 用 AsIs 后路由只依赖域名规则，境外域名统一由服务器侧解析。
	b.WriteString(`    "domainStrategy": "AsIs",` + "\n")
	b.WriteString("    \"rules\": " + routingRules(p.Mode) + "\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func (p Params) validate() error {
	switch {
	case p.Address == "":
		return fmt.Errorf("缺少服务器地址")
	case p.Port <= 0 || p.Port > 65535:
		return fmt.Errorf("服务器端口不合法：%d", p.Port)
	case p.UUID == "":
		return fmt.Errorf("缺少连接身份（UUID）")
	case p.PublicKey == "":
		return fmt.Errorf("缺少 REALITY 公钥")
	case p.SNI == "":
		return fmt.Errorf("缺少伪装域名（SNI）")
	}
	// 通道B的失败要在这里就说清楚。留到内核启动时才报的话，
	// 用户看到的是一句与真实原因无关的「配置错误」。
	if p.Protocol == ProtoHysteria {
		switch {
		case !p.HysteriaEnabled:
			return fmt.Errorf("服务端未启用通道B")
		case p.HysteriaPort <= 0 || p.HysteriaPort > 65535:
			return fmt.Errorf("通道B端口不合法：%d", p.HysteriaPort)
		case p.HysteriaObfs == "":
			return fmt.Errorf("缺少通道B混淆密钥")
		case p.HyAuth == "":
			return fmt.Errorf("缺少通道B认证信息")
		}
	}
	return nil
}

// proxyOutbound 按所选通道生成 proxy 出站。
//
// 两条通道只在这里分岔，入站与路由完全共用：
//   - 通道A：由内核自己建 VLESS + REALITY 隧道；
//   - 通道B：出站只是一个本机 SOCKS5，真正的隧道由同进程的 hysteria 客户端负责。
//
// 因此分流规则与 TUN 接管不必写两套，也就不可能出现「两条通道行为不一致」。
func proxyOutbound(p Params) string {
	if p.Protocol == ProtoHysteria {
		port := p.HysteriaSocksPort
		if port <= 0 {
			// 端口缺失时兜底到默认值：宁可连不上并报错，
			// 也不要生成一份 port:0 的非法配置让内核直接拒绝启动。
			port = DefaultHySocksPort
		}
		return fmt.Sprintf(`    {
      "tag": "proxy",
      "protocol": "socks",
      "settings": {
        "servers": [
          {
            "address": "127.0.0.1",
            "port": %d
          }
        ]
      }
    }`, port)
	}
	return realityOutbound(p)
}

// tunInbound 让内核接管 VpnService 交进来的虚拟网卡。
//
// 地址、DNS、路由都不在这里配——Android 侧由 VpnService.Builder 负责，
// 与 Windows 端「内核只建网卡、系统配置自己做」是同一个思路。
func tunInbound() string {
	return fmt.Sprintf(`    {
      "tag": "tun-in",
      "port": 0,
      "protocol": "tun",
      "settings": {
        "name": %q,
        "MTU": %d,
        "user_level": 0
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }`, tunName, tunMTU)
}

// socksInbound 开一个 SOCKS 入口，默认只在 127.0.0.1 上，方便单独验证隧道；
// listen 传 0.0.0.0 时同一局域网的设备也能用。
func socksInbound(port int, listen string) string {
	return fmt.Sprintf(`    {
      "tag": "socks-in",
      "listen": %q,
      "port": %d,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }`, listen, port)
}

// realityOutbound 是通道 A：由内核直接建 VLESS + XTLS-Vision + REALITY 隧道。
func realityOutbound(p Params) string {
	return fmt.Sprintf(`    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": %q,
            "port": %d,
            "users": [
              {
                "id": %q,
                "encryption": "none",
                "flow": %q
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": %q,
          "fingerprint": %q,
          "password": %q,
          "shortId": %q,
          "spiderX": %q
        }
      }
    }`, p.Address, p.Port, p.UUID, p.Flow,
		p.SNI, p.Fingerprint, p.PublicKey, p.ShortID, p.SpiderX)
}

// routingRules 生成路由规则，与 Windows 端保持同一套语义。
//
// 两个模式都包含这条：目标为 IPv6 字面地址时直连。
// 结合出站侧不使用 IPv6，代理链路不会承载任何 IPv6 流量，IPv6 一律走本机。
func routingRules(mode string) string {
	var b strings.Builder
	b.WriteString("[\n")
	b.WriteString(`      {
        "type": "field",
        "outboundTag": "block",
        "protocol": ["bittorrent"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": ["geoip:private", "::/0"]
      }`)
	if mode != ModeGlobal {
		b.WriteString(`,
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": ["geosite:private", "geosite:cn"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": ["geoip:cn"]
      }`)
	}
	b.WriteString("\n    ]")
	return b.String()
}
