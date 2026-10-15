package ctl

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 服务端固定路径。内核二进制与配置路径沿用官方安装脚本的位置。
const (
	XrayBin     = "/usr/local/bin/xray"
	XrayCfgPath = "/usr/local/etc/xray/config.json"
	InboundTag  = "reality-in"
	// XrayAccessLog 是内核访问日志路径。
	//
	// 监控就是靠它拿到「哪个账号访问了哪个域名」。之所以必须是文件而不是 stdout：
	// stdout 进了 journald，读它要么依赖 journalctl 的输出格式，要么拿不到稳定的
	// 读取偏移（每读一次都得重扫），而文件可以记住偏移量增量读。
	//
	// 内核自己不轮转这个文件，由控制面在它涨到阈值时清空，见 monitor.go。
	XrayAccessLog = "/var/log/xray/access.log"
)

// CfgTempPath 返回「先写临时文件 → 自校验 → 原子改名」里那个临时文件的路径。
//
// 后缀必须加在**扩展名之前**：Xray 用 serial.GetFormat 按文件扩展名判断配置格式，
// 写成 config.json.new 它会认不出这是 JSON，直接拒绝启动并报
//
//	Failed to start: main: failed to load config files: [...] > core: Failed to get format of ...
//
// hysteria 同样按扩展名区分 yaml/json，所以两边都用这个函数。
//
// 这个坑只在**真正部署到新机器**时才暴露：控制面与 transctl 写完就改名、不把临时
// 文件交给内核校验，只有 cmd/transrelay 会跑 `xray -test`（分支节点A第一次部署时踩到）。
func CfgTempPath(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + ".new" + ext
}

// ServerSettings 是服务端固定参数，与账号无关，只写一次。
type ServerSettings struct {
	Domain      string `json:"domain"`
	ListenPort  int    `json:"listenPort"`
	SNI         string `json:"sni"`
	Target      string `json:"target"`
	PrivateKey  string `json:"privateKey"`
	ShortID     string `json:"shortId"`
	APIPort     int    `json:"apiPort"`
	Fingerprint string `json:"fingerprint"`
	Flow        string `json:"flow"`

	// 第二条通道（Hysteria2，UDP）的参数。未部署时 Enabled 为假，整套系统按单通道运行。
	// 这些值随登录响应下发给客户端，所以客户端不需要内置任何口令。
	// 两个 Stats 字段标了 json:"-"，它们只存在于 hysteria.json，不写进本设置文件。
	HysteriaEnabled     bool   `json:"hysteriaEnabled,omitempty"`
	HysteriaPort        int    `json:"hysteriaPort,omitempty"`
	HysteriaObfs        string `json:"hysteriaObfs,omitempty"`
	HysteriaStatsListen string `json:"-"`
	HysteriaStatsSecret string `json:"-"`

	// DownloadPath 是下载页的深层路径（不含首尾斜杠）。
	// 刻意取得不像业务路径，且根路径不留任何入口，避免被扫描器发现。
	// 留空表示不启用下载页。
	DownloadPath string `json:"downloadPath,omitempty"`
	// DownloadDir 是安装包存放目录。目录内只暴露 .apk，且不可枚举。
	DownloadDir string `json:"downloadDir,omitempty"`

	// NodeID / NodeName 是本机在多线路体系里的标识与显示名。
	// 显示名随登录响应下发（客户端线路下拉框里显示的就是它），所以改名不用重发客户端。
	NodeID   string `json:"nodeId,omitempty"`
	NodeName string `json:"nodeName,omitempty"`
	// NodesPath 是中转节点登记表（nodes.json）的位置。
	// 留空表示不启用中转，整套系统按单线路运行；LoadServerSettings 会把它补成
	// 与 server.json 同目录下的 nodes.json。
	NodesPath string `json:"nodesPath,omitempty"`
}

// DefaultServerSettings 返回与账号无关的固定参数默认值。
//
// 刻意**不包含** REALITY 私钥与 shortId：这两个值合起来就是这个节点的身份，
// 谁拿到谁就能冒充它把客户端流量终结在自己手里。写进源码等于随代码一起泄露
// （仓库、打包产物、离职人员手里的副本都算），而且没法在不改代码的前提下轮换。
//
// 它们在首次初始化时随机生成并落盘，见 ensureNodeIdentity。
func DefaultServerSettings() ServerSettings {
	return ServerSettings{
		Domain:      "proxy.example.com",
		ListenPort:  443,
		SNI:         "www.samsung.com",
		Target:      "www.samsung.com:443",
		APIPort:     10085,
		Fingerprint: "chrome",
		Flow:        "xtls-rprx-vision",
		// 双通道默认端口：UDP。与控制面的 TCP 8443 同号但协议不同，互不冲突。
		HysteriaPort: 8443,
	}
}

// ensureNodeIdentity 为缺失的身份凭据生成新值。
//
// 只在「首次初始化」或「配置文件里没有这两个字段」时调用：
// 已有部署的私钥绝不能重新生成，否则所有已发出的客户端连接参数会立刻全部失效。
func ensureNodeIdentity(s *ServerSettings) error {
	if s.PrivateKey == "" {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("生成 REALITY 私钥失败: %w", err)
		}
		s.PrivateKey = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	}
	if s.ShortID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("生成 shortId 失败: %w", err)
		}
		s.ShortID = hex.EncodeToString(b)
	}
	return nil
}

// LoadServerSettings 读取固定参数，不存在时写入默认值。
func LoadServerSettings(path string) (ServerSettings, error) {
	s := DefaultServerSettings()
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return s, err
		}
		if err := ensureNodeIdentity(&s); err != nil {
			return s, err
		}
		out, _ := json.MarshalIndent(s, "", "  ")
		if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
			return s, err
		}
		return s, os.WriteFile(path, out, 0o600)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("服务端参数不是合法 JSON: %w", err)
	}
	// 老配置文件里可能没有身份凭据（或为空），就地补齐并回写。
	if s.PrivateKey == "" || s.ShortID == "" {
		if err := ensureNodeIdentity(&s); err != nil {
			return s, err
		}
		out, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(path, out, 0o600); err != nil {
			return s, err
		}
	}
	// 中转节点登记表默认与 server.json 同目录；没有这个文件就是单线路部署。
	if s.NodesPath == "" {
		s.NodesPath = dirOf(path) + "/nodes.json"
	}
	// 同目录下的 hysteria.json 存在即表示双通道已部署，就地补进参数。
	// 这样调用方拿到的 ServerSettings 天然包含两条通道的信息，不必在别处再读一次文件，
	// 也就不会出现「两处状态不一致」这类难查的问题。
	if h, ok := loadHysteriaFile(dirOf(path) + "/hysteria.json"); ok {
		s.HysteriaEnabled = true
		if h.Port != 0 {
			s.HysteriaPort = h.Port
		}
		s.HysteriaObfs = h.Obfs
		s.HysteriaStatsListen = h.StatsListen
		s.HysteriaStatsSecret = h.StatsSecret
	}
	return s, nil
}

// XrayRunGID 返回内核运行用户（nobody）的组 ID，用于给内核配置文件设置合适的组权限。
//
// 为什么需要它：那份配置里有全部账号的 UUID（等价于连接凭据）与 REALITY 私钥，
// 不能给其他本地用户读到；但内核以 nobody 运行，0600 它又读不到自己的配置而起不来。
// 折中就是 root:<nobody 的组> + 0640。
//
// 拿不到时返回 -1，调用方退回 0644 并记一行警告：
// 宁可留一个已知的权限问题，也不要让内核读不到配置导致整个代理不可用。
func XrayRunGID() int {
	u, err := user.Lookup("nobody")
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return -1
	}
	return gid
}

// XrayRunUID 返回内核运行用户（nobody）的 UID，拿不到时返回 -1。
//
// 与 XrayRunGID 成对使用：**访问日志文件的属主必须是内核用户**。
// 因为创建它的往往是「以 root 跑的 `xray run -test`」（配置自校验），
// 而真正以 nobody 启动的内核随后就打不开那个 root:root 的文件了，
// 报的是 "open .../access.log: permission denied" —— 看日志的人只会怀疑权限配置，
// 不会想到是前一步的自校验把文件占了。
func XrayRunUID() int {
	u, err := user.Lookup("nobody")
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}

func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "."
	}
	return p[:i]
}

// PublicKey 由私钥推导 REALITY 公钥。
//
// 内核的 x25519 工具输出里那行 "Password (PublicKey)" 就是这个值。
// 这里用标准库的 X25519 直接算，避免依赖外部命令。
func (s ServerSettings) PublicKey() (string, error) {
	return publicKeyOf(s.PrivateKey)
}

// publicKeyOf 由 REALITY 私钥推导公钥。
//
// 抽成独立函数是因为中转节点也要做同一件事（见 relay.go）：
// 一处实现、两处调用，免得哪边改了另一边忘了跟。
func publicKeyOf(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("私钥不是合法 base64url: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("私钥应为 32 字节，实际 %d", len(raw))
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("私钥无法用于 X25519: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// Params 是发给客户端的连接参数，不含任何服务端机密。
type Params struct {
	Address     string `json:"address"`
	Port        int    `json:"port"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
	Flow        string `json:"flow"`

	// 第二条通道由服务端决定并下发，客户端据此显示/隐藏协议选项，
	// 也就不需要在任何地方内置对口令的假设。
	HysteriaEnabled bool   `json:"hysteriaEnabled"`
	HysteriaPort    int    `json:"hysteriaPort"`
	HysteriaObfs    string `json:"hysteriaObfs"`
	// HysteriaSNI 是通道B 握手用的服务器名，留空表示就用 Address。
	// 中转线路必须显式给（填出口节点的域名），否则客户端会拿中转节点的 IP
	// 去校验证书而必然失败。客户端的同名字段见 common.Params.HysteriaSNI。
	HysteriaSNI string `json:"hysteriaSNI,omitempty"`
}

// ClientParams 组装客户端连接参数。
func (s ServerSettings) ClientParams() (Params, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return Params{}, err
	}
	return Params{
		Address:     s.Domain,
		Port:        s.ListenPort,
		SNI:         s.SNI,
		PublicKey:   pub,
		ShortID:     s.ShortID,
		Fingerprint: s.Fingerprint,
		Flow:        s.Flow,

		HysteriaEnabled: s.HysteriaEnabled,
		HysteriaPort:    s.HysteriaPort,
		HysteriaObfs:    s.HysteriaObfs,
	}, nil
}

// RenderXrayConfig 依据固定参数与账号列表生成内核配置。
//
// 生成结果由控制服务独占管理，不要手工修改——改了会在下一次渲染时被覆盖。
func RenderXrayConfig(s ServerSettings, users []User) ([]byte, error) {
	type client struct {
		ID    string `json:"id"`
		Flow  string `json:"flow"`
		Email string `json:"email"`
	}
	clients := make([]client, 0, len(users))
	for _, u := range users {
		if !u.Enabled {
			continue
		}
		clients = append(clients, client{ID: u.UUID, Flow: s.Flow, Email: u.Name})
	}

	cfg := map[string]any{
		// access 指向文件：访问记录采集要靠它按偏移增量读，见 XrayAccessLog。
		"log": map[string]any{"loglevel": "warning", "access": XrayAccessLog},
		// 打开统计与 API 服务，控制服务靠它读流量、在运行时增删用户。
		"api":   map[string]any{"tag": "api", "services": []string{"StatsService", "HandlerService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			// level 0 是客户端默认等级，按用户统计上下行必须在这里打开。
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds": []any{
			map[string]any{
				"tag": "api", "listen": "127.0.0.1", "port": s.APIPort,
				"protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1"},
			},
			map[string]any{
				"tag": InboundTag, "listen": "0.0.0.0", "port": s.ListenPort, "protocol": "vless",
				"settings": map[string]any{"clients": clients, "decryption": "none"},
				"streamSettings": map[string]any{
					"network": "tcp", "security": "reality",
					"realitySettings": map[string]any{
						"show": false, "target": s.Target, "xver": 0,
						"serverNames": []string{s.SNI},
						"privateKey":  s.PrivateKey,
						"shortIds":    []string{s.ShortID},
					},
				},
				"sniffing": map[string]any{
					"enabled": true, "destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		"outbounds": []any{
			// UseIPv4：代理出去的域名只解析到 IPv4，从服务端侧确保代理链路不承载 IPv6。
			map[string]any{"tag": "direct", "protocol": "freedom",
				"settings": map[string]any{"domainStrategy": "UseIPv4"}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
			map[string]any{"tag": "api", "protocol": "freedom"},
		},
		"routing": map[string]any{
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
				map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// ---------- 内核 API 封装 ----------

// TrafficPair 是内核计数器里某个用户的原始上下行字节数。
type TrafficPair struct {
	Up   int64
	Down int64
}

var (
	reStatEntry = regexp.MustCompile(`user>>>([^>]+)>>>traffic>>>(uplink|downlink)`)
	reInt       = regexp.MustCompile(`\d+`)
)

// QueryTraffic 读取所有用户的原始流量计数器。
//
// 返回的是内核开机以来的累计值，会随内核重启归零，调用方需要自行做增量累加。
func QueryTraffic(apiPort int, timeout time.Duration) (map[string]TrafficPair, error) {
	cmd := exec.Command(XrayBin, "api", "statsquery",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort),
		"-timeout", strconv.Itoa(int(timeout.Seconds())),
		"-pattern", "user>>>")
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil && !strings.Contains(text, "user>>>") {
		return nil, fmt.Errorf("读取流量失败: %v (%s)", err, strings.TrimSpace(text))
	}
	return parseTrafficText(text), nil
}

// parseTrafficText 解析内核 statsquery 的输出。
// 抽成独立函数是为了能用真实输出样本做单元测试，这个解析曾经因为类型写错而静默读成 0。
func parseTrafficText(text string) map[string]TrafficPair {
	res := map[string]TrafficPair{}

	// 形态一：JSON，形如 {"stat":[{"name":"user>>>a>>>traffic>>>uplink","value":1396}]}
	// 注意 value 是数字而不是字符串：必须用 json.Number 接收，否则反序列化会直接失败，
	// 然后悄悄落到下面的文本分支，把所有用量都读成 0。
	var doc struct {
		Stat []struct {
			Name  string      `json:"name"`
			Value json.Number `json:"value"`
		} `json:"stat"`
	}
	if json.Unmarshal([]byte(text), &doc) == nil {
		for _, e := range doc.Stat {
			m := reStatEntry.FindStringSubmatch(e.Name)
			if m == nil {
				continue
			}
			n, _ := e.Value.Int64()
			applyStat(res, m[1], m[2], n)
		}
		return res
	}

	// 形态二：纯文本兜底。名称与数值可能分处两行，所以先记住条目、再吃下一行里的数字。
	pending, pendingDir := "", ""
	for _, line := range strings.Split(text, "\n") {
		if m := reStatEntry.FindStringSubmatch(line); m != nil {
			pending, pendingDir = m[1], m[2]
			continue
		}
		if pending == "" {
			continue
		}
		if s := reInt.FindString(line); s != "" {
			n, _ := strconv.ParseInt(s, 10, 64)
			applyStat(res, pending, pendingDir, n)
			pending = ""
		}
	}
	return res
}

func applyStat(res map[string]TrafficPair, name, dir string, n int64) {
	p := res[name]
	if dir == "uplink" {
		p.Up = n
	} else {
		p.Down = n
	}
	res[name] = p
}

// AddUserRuntime 在运行中的内核里加上一个用户，不需要重启、不影响其他在线用户。
func AddUserRuntime(apiPort int, s ServerSettings, u User, timeout time.Duration) error {
	doc := map[string]any{
		"inbounds": []any{
			map[string]any{
				// port 必须带上：片段里不写 listen 时默认为 AnyIP，
				// 内核会以 "Listen on AnyIP but no Port(s) set" 拒绝构建该入站，用户就加不进去。
				"tag": InboundTag, "protocol": "vless", "port": s.ListenPort,
				"settings": map[string]any{
					"decryption": "none",
					"clients":    []any{map[string]any{"id": u.UUID, "flow": s.Flow, "email": u.Name}},
				},
			},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	// 用 CreateTemp 而不是自己拼 /tmp 下的固定文件名。
	//
	// 拼固定名字（哪怕带了账号名）等于把路径交给别人预判：本机任何低权用户都能
	// 提前建一个同名符号链接指向 /etc/ 下的目标文件，而控制面以 root 运行、
	// os.WriteFile 默认跟随符号链接 —— 一次「新增账号」就能覆写系统文件。
	// CreateTemp 用 O_EXCL 独占创建，从根上消掉这个可能。
	f, err := os.CreateTemp("", "transctl-adu-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	// 这个临时文件只由本进程读取（内容是传给内核 api 子命令的参数），
	// 所以 0600 就够。显式设一次，避免受 umask 影响。
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// 参数顺序很关键：文件路径是位置参数，flag 必须写在它之前，
	// 否则内核会把 --server 当成又一个待加载的文件名而直接报错。
	cmd := exec.Command(XrayBin, "api", "adu",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort),
		"-timeout", strconv.Itoa(int(timeout.Seconds())),
		tmp)
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil {
		return fmt.Errorf("添加用户失败: %v (%s)", err, strings.TrimSpace(text))
	}
	// 内核即使在「一个用户都没加上」的情况下也返回 0，必须核对输出确认真的加成功，
	// 否则就是静默失败——这正是之前踩过的坑。
	if !strings.Contains(text, "Added 1 user(s)") {
		return fmt.Errorf("添加用户未生效: %s", strings.TrimSpace(text))
	}
	return nil
}

// RemoveUserRuntime 在运行中的内核里摘掉一个用户，用于删号或改密后作废旧身份。
func RemoveUserRuntime(apiPort int, name string, timeout time.Duration) error {
	cmd := exec.Command(XrayBin, "api", "rmu",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort),
		"-timeout", strconv.Itoa(int(timeout.Seconds())),
		"-tag="+InboundTag, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("移除用户失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// OnlineSessions 查询某个用户当前的活跃会话数。
func OnlineSessions(apiPort int, name string, timeout time.Duration) (int, error) {
	cmd := exec.Command(XrayBin, "api", "statsonline",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort),
		"-timeout", strconv.Itoa(int(timeout.Seconds())),
		"-email", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// 完全没有在线会话时内核返回 NotFound，属于正常情况而不是故障。
		if strings.Contains(string(out), "not found") {
			return 0, nil
		}
		return 0, err
	}
	n, _ := strconv.Atoi(reInt.FindString(string(out)))
	return n, nil
}

// SinceText 把时间戳格式化为相对时间，用于展示「最近活动」。
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

// UserCount 返回内核中某个入站当前真正生效的用户数量。
// 用于核对「运行中的内核」与「账号库」是否一致：只比对配置文件是不够的，
// 运行时增删用户失败会造成两者静默分叉，表现为账号明明存在却连不上。
func UserCount(apiPort int, tag string, timeout time.Duration) (int, error) {
	cmd := exec.Command(XrayBin, "api", "inboundusercount",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort),
		"-timeout", strconv.Itoa(int(timeout.Seconds())),
		"-tag="+tag)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("查询内核用户数失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	n, err := strconv.Atoi(reInt.FindString(string(out)))
	if err != nil {
		return 0, fmt.Errorf("无法解析内核用户数: %s", strings.TrimSpace(string(out)))
	}
	return n, nil
}
