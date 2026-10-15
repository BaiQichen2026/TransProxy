package common

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// 分流模式。
const (
	// ModeSmart 只代理境外域名与 IP，国内与内网直连。这是默认模式。
	ModeSmart = "smart"
	// ModeGlobal 除内网外全部走代理。
	ModeGlobal = "global"
)

// Notice 是必须向用户展示的声明。
const Notice = "本软件完全免费，仅供学习与网络技术研究使用，请勿用于任何违反当地法律法规的用途。"

// NoticeLines 把声明按行拆开供界面展示。
// 单行标签会被文字内容撑开，进而把整个窗口顶得很宽，所以界面上必须分行显示。
func NoticeLines() []string {
	return []string{
		"本软件完全免费，仅供学习与网络技术研究使用。",
		"请勿用于任何违反当地法律法规的用途。",
	}
}

// SinceText 把时间戳格式化为相对时间，用于展示「最近活动」。
// 这里与 ctl.SinceText 是同一套逻辑：服务端包不能反向依赖客户端包（客户端包含 Windows 专有 syscall），
// 所以两边各留一份小工具，而不是硬凑一个共享包。
func SinceText(unix int64) string {
	if unix <= 0 {
		return "从未"
	}
	d := time.Since(time.Unix(unix, 0))
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
}

// ModeLabel 返回模式的中文名，供界面展示。
func ModeLabel(mode string) string {
	switch mode {
	case ModeGlobal:
		return "全局代理"
	default:
		return "智能分流（仅代理境外）"
	}
}

// Profile 描述一条客户端连接配置。
//
// 这里有两个容易混淆的地址，务必分清：
//   - ServerAddr 是客户端实际连接的入口，用域名，好处是服务器 IP 变更时客户端无需重发配置；
//   - SNI 是 REALITY 借用的伪装站点域名，与入口域名无关，必须与服务端一致。
type Profile struct {
	Remark      string
	ServerAddr  string
	ServerPort  int
	UUID        string
	Flow        string
	SNI         string
	PublicKey   string
	ShortID     string
	Fingerprint string
	SpiderX     string
	SocksPort   int
	HTTPPort    int
	// ListenAddr 是本地代理入站（SOCKS / HTTP）绑定的地址。
	// 空表示只允许本机使用，与旧版本行为一致；设为 ListenAny 之后，
	// 同一局域网内的其它设备（例如自己的服务器）就能通过
	// 「本机 IP + SOCKS 端口」借这条隧道上网。
	//
	// 开放前要清楚：SOCKS 入站是 noauth 的，网内任何人都能白用这个出口。
	ListenAddr string
	Mode       string
	// SendThrough 是物理网卡的本地 IPv4。TUN 模式下必须给 direct 出站设置它：
	// 国内流量被规则判为直连后，由 freedom 出站发起连接，而这条连接的目的地是
	// 国内公网 IP，既不命中绕行路由、又会落进 0.0.0.0/1 接管路由回到 TUN，
	// 形成死循环（现象就是「外网通、国内站全打不开」）。
	// 绑定源地址后由操作系统按源地址选路，直接走物理网卡，从根上避开这个环。
	SendThrough string
	// TunMode 为真时启用 TUN 虚拟网卡，接管系统全部 IPv4 流量。需要管理员权限。
	TunMode bool

	// Protocol 选择走哪条通道：auto 由客户端测速决定，其余为强制指定。
	Protocol string
	// 第二条通道（Hysteria2）的参数，由服务端随登录响应下发。
	HysteriaEnabled bool
	HysteriaPort    int
	HysteriaObfs    string
	// HysteriaSNI 是通道B 握手用的服务器名，见 Params.HysteriaSNI。
	// 空表示就用 ServerAddr（直连线路的情形）。
	HysteriaSNI string
	// HysteriaSocksPort 是本机 hysteria 客户端监听的 SOCKS 端口。
	// xray 通过它把流量交给 hysteria，因此分流与 TUN 逻辑对两条通道完全一致。
	HysteriaSocksPort int
}

// 通道标识。auto 不是「第三条通道」，而是让客户端启动时测速择优。
const (
	ProtoAuto     = "auto"
	ProtoReality  = "reality"
	ProtoHysteria = "hysteria"
)

// ProtocolLabel 返回通道的中文名，供界面展示。
func ProtocolLabel(p string) string {
	switch p {
	case ProtoReality:
		return "通道A · REALITY（最隐蔽）"
	case ProtoHysteria:
		return "通道B · Hysteria2（抗丢包）"
	default:
		return "智能优选"
	}
}

// Default 返回默认参数（服务器地址与端口，不含账号身份）。
func Default() Profile {
	return Profile{
		Remark:      "Seoul-REALITY",
		ServerAddr:  "proxy.example.com",
		ServerPort:  443,
		Flow:        "xtls-rprx-vision",
		SNI:         "www.samsung.com",
		Fingerprint: "chrome",
		SpiderX:     "/",
		// 刻意避开 10808/10809（v2rayN 的默认端口）与 7890（Clash 的默认端口）：
		// 用户很可能同时装着别的客户端，撞端口会导致新内核绑定失败，
		// 而端口探测却因为旧进程占着而「成功」，表现为一堆莫名其妙的错乱。
		SocksPort:         17900,
		HTTPPort:          17901,
		HysteriaSocksPort: DefaultHysteriaSocksPort,
		Mode:              ModeSmart,
	}
}

// 本地代理入站的绑定地址。
const (
	// ListenLocal 只允许本机访问，是默认值。
	ListenLocal = "127.0.0.1"
	// ListenAny 允许局域网访问。入站是无认证的 SOCKS/HTTP，
	// 只在可信网络里开启。
	ListenAny = "0.0.0.0"
)

// listenAddr 返回入站实际绑定的地址，未设置时按「仅本机」处理。
// 这样旧版本客户端配置里没有这个字段时，行为也不会变。
func (p Profile) listenAddr() string {
	if strings.TrimSpace(p.ListenAddr) == "" {
		return ListenLocal
	}
	return p.ListenAddr
}

// DefaultHysteriaSocksPort 是旁挂的 hysteria 客户端监听的 SOCKS 端口。
// xray 把 proxy 出站指向它，因此它属于「本机内部端口」，同样要避开常见客户端占用的段。
const DefaultHysteriaSocksPort = 17902

// FromParams 把服务端下发的连接参数与账号身份合成本地配置。
func FromParams(p Params, uuid, mode string, socksPort, httpPort int) Profile {
	hyPort := p.HysteriaPort
	if hyPort == 0 {
		// 服务端配置缺省时兜底到约定的 8443，避免下发字段不全直接导致通道不可用。
		hyPort = 8443
	}
	return Profile{
		Remark:      "节点",
		ServerAddr:  p.Address,
		ServerPort:  p.Port,
		UUID:        uuid,
		Flow:        p.Flow,
		SNI:         p.SNI,
		PublicKey:   p.PublicKey,
		ShortID:     p.ShortID,
		Fingerprint: p.Fingerprint,
		SpiderX:     "/",
		SocksPort:   socksPort,
		HTTPPort:    httpPort,
		Mode:        mode,

		HysteriaEnabled:   p.HysteriaEnabled,
		HysteriaPort:      hyPort,
		HysteriaObfs:      p.HysteriaObfs,
		HysteriaSNI:       p.HysteriaSNI,
		HysteriaSocksPort: DefaultHysteriaSocksPort,
	}
}

// HysteriaAvailable 判断服务端是否下发了可用的第二条通道。
// 三项参数缺一不可：少了混淆密钥或端口，即便服务端「启用」了也连不上。
func (p Profile) HysteriaAvailable() bool {
	return p.HysteriaEnabled && p.HysteriaPort > 0 && p.HysteriaObfs != ""
}

// routingRules 按分流模式生成路由规则。
//
// 两个模式都包含这条：目标为 IPv6 字面地址时直连。
// 结合出口侧的 UseIPv4，代理链路不会承载任何 IPv6 流量，IPv6 一律走本机。
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
	// 智能分流：国内域名与国内 IP 直连，其余（境外）走代理。
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

const (
	// tunInbound 只负责一件事：让内核创建虚拟网卡并接管包处理。
	// 地址、DNS、路由刻意都不在这里配——那三件事由 tunsetup.go 用 netsh/route
	// 自己做，原因见那里的说明（内核的自动配置在 Windows 上会静默失败）。
	tunInbound = `    {
      "tag": "tun-in",
      "protocol": "tun",
      "settings": {
        "name": "TransProxy",
        "desc": "TransProxy",
        "mtu": 1400,
        "userLevel": 0,
        "autoOutboundsInterface": "auto"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    },
`

	// 系统侧的地址、DNS、路由见 tunsetup.go。这里不再生成 dns 段与 dns-out 出站：
	// DNS 查询由绕行路由直接经物理网卡发出，根本不进 TUN，也就无需内核代管。
)

// ClientConfig 生成完整的客户端配置。
//
// domainStrategy 特意选择 AsIs 而不是常见的 IPIfNonMatch：后者会为了补足 IP 规则
// 而用本地 DNS 解析域名，被墙域名在本地常被污染成国内 IP，反而命中 geoip:cn 被误判为
// 直连导致访问失败。使用 AsIs 后路由只依赖域名规则，境外域名统一由服务器侧解析。
func ClientConfig(p Profile) string {
	// TUN 模式只多出一个 tun 入站；普通代理模式产出的配置与之前逐字一致。
	inbound := ""
	if p.TunMode {
		inbound = tunInbound
	}
	// direct 出站绑定物理网卡源地址，理由见 Profile.SendThrough。
	directExtra := ""
	if p.TunMode && p.SendThrough != "" {
		directExtra = fmt.Sprintf(",\n      \"sendThrough\": %q", p.SendThrough)
	}
	return fmt.Sprintf(`{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
%s    {
      "tag": "socks-in",
      "listen": "%s",
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
    },
    {
      "tag": "http-in",
      "listen": "%s",
      "port": %d,
      "protocol": "http",
      "settings": {
        "allowTransparent": false
      }
    }
  ],
  "outbounds": [
%s,
    {
      "tag": "direct",
      "protocol": "freedom"%s
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": %s
  }
}
`,
		inbound,
		p.listenAddr(), p.SocksPort,
		p.listenAddr(), p.HTTPPort,
		proxyOutbound(p),
		directExtra,
		routingRules(p.Mode),
	)
}

// proxyOutbound 按所选通道生成 proxy 出站。
//
// 两条通道只在这里分岔，入站与路由完全共用：
//   - REALITY：由内核直接建 VLESS 隧道；
//   - Hysteria2：出站只是一个本机 SOCKS5，真正的隧道由旁边的 hysteria 进程负责。
//
// 这样分流规则与 TUN 接管不必写两套，也就不可能出现「两条通道行为不一致」这类问题。
func proxyOutbound(p Profile) string {
	if p.Protocol == ProtoHysteria {
		// 端口缺失时兜底到默认值：宁可连不上并报错，也不要生成一份
		// `port: 0` 的非法配置让内核直接拒绝启动。
		port := p.HysteriaSocksPort
		if port <= 0 {
			port = DefaultHysteriaSocksPort
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
	return fmt.Sprintf(`    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "%s",
            "port": %d,
            "users": [
              {
                "id": "%s",
                "encryption": "none",
                "flow": "%s"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "%s",
          "fingerprint": "%s",
          "password": "%s",
          "shortId": "%s",
          "spiderX": "%s"
        }
      }
    }`,
		p.ServerAddr, p.ServerPort, p.UUID, p.Flow,
		p.SNI, p.Fingerprint, p.PublicKey, p.ShortID, p.SpiderX)
}

// HysteriaConfig 生成 hysteria 客户端配置（YAML）。
//
// 保持证书校验开启：服务端用的是 proxy.example.com 的正规证书，
// 关掉校验等于放弃「确认对面确实是自己的服务器」这一层保障。
func HysteriaConfig(p Profile, username, password string) string {
	port := p.HysteriaPort
	if port <= 0 {
		port = 8443
	}
	// SNI 与「连到哪」是两件事，必须分开取值。
	//
	// 走中转线路时 server 是第一跳（分支节点A，可能就是个 IP），而证书是出口
	// （总节点）域名的 —— 这时只有用出口域名做 SNI 才校验证得过。
	// 若写成 p.ServerAddr，现象是「中转线路的通道B 必连不上」，而且报错只会说
	// 证书校验失败，很难反推到是 SNI 取错了。
	sni := p.HysteriaSNI
	if sni == "" {
		sni = p.ServerAddr
	}
	return fmt.Sprintf(`server: %s:%d
auth: "%s:%s"
tls:
  sni: %s
obfs:
  type: salamander
  salamander:
    password: %s
socks5:
  listen: 127.0.0.1:%d
`, p.ServerAddr, port, username, password,
		sni, p.HysteriaObfs, p.HysteriaSocksPort)
}

// ShareLink 生成 vless:// 分享链接，可被 v2rayN / v2rayNG / NekoBox 直接导入。
func ShareLink(p Profile) string {
	return fmt.Sprintf(
		"vless://%s@%s:%d?encryption=none&flow=%s&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&spx=%%2F&type=tcp&headerType=none#%s",
		p.UUID, p.ServerAddr, p.ServerPort, p.Flow,
		p.SNI, p.Fingerprint, p.PublicKey, p.ShortID,
		url.QueryEscape(p.Remark),
	)
}
