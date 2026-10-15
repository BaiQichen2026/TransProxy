package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIClient 访问服务端控制面（HTTPS）。
type APIClient struct {
	base string
	hc   *http.Client
}

// Params 是服务端下发的连接参数。
type Params struct {
	Address     string `json:"address"`
	Port        int    `json:"port"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	Fingerprint string `json:"fingerprint"`
	Flow        string `json:"flow"`
	// 第二条通道（Hysteria2）参数。服务端没部署或没启用时 HysteriaEnabled 为 false，
	// 客户端据此把「通道B」判定为不可用，而不是等到连接时才失败。
	HysteriaEnabled bool   `json:"hysteriaEnabled"`
	HysteriaPort    int    `json:"hysteriaPort"`
	HysteriaObfs    string `json:"hysteriaObfs"`
	// HysteriaSNI 是通道B 做 TLS 握手时用的服务器名，留空表示就用 Address。
	//
	// 落地线路必须单独给：那时 Address 是落地节点的地址（比如分支节点A的 IP），
	// 而证书是**借用出口域名（总节点）的**，拿 IP 当 SNI 去校验证书必然失败。
	// 留出这个字段，是为了让「连到哪」和「证书上写的谁」能分开。
	HysteriaSNI string `json:"hysteriaSNI,omitempty"`
}

// HysteriaServerName 返回通道B 握手该用的服务器名。
func (p Params) HysteriaServerName() string {
	if p.HysteriaSNI != "" {
		return p.HysteriaSNI
	}
	return p.Address
}

// LoginResult 是登录成功后的返回。
// UUID 是该账号在内核里的身份（等价于连接凭据），只在登录/取参数接口回给通过认证的本人。
type LoginResult struct {
	Username string `json:"username"`
	Note     string `json:"note"`
	Token    string `json:"token"`
	ExpireAt int64  `json:"expireAt"`
	UUID     string `json:"uuid"`
	Params   Params `json:"params"`
	// Instances 是服务端下发的可选线路表，第一项就是默认线路。
	//
	// 老客户端会整个忽略它、继续用上面的 Params —— 那份正是默认线路的参数，
	// 所以新旧两端可以任意组合，不会互相踢下线。
	Instances []Instance `json:"instances,omitempty"`
}

// Profile 把登录结果合成本地连接配置。
func (r *LoginResult) Profile(mode string, socksPort, httpPort int) Profile {
	return FromParams(r.Params, r.UUID, mode, socksPort, httpPort)
}

// Traffic 是流量接口返回。
type Traffic struct {
	UsedBytes      int64 `json:"usedBytes"`
	QuotaBytes     int64 `json:"quotaBytes"`
	RemainingBytes int64 `json:"remainingBytes"`
	SessionUp      int64 `json:"sessionUp"`
	SessionDown    int64 `json:"sessionDown"`
	UpSpeed        int64 `json:"upSpeed"`
	DownSpeed      int64 `json:"downSpeed"`
	OnlineSessions int   `json:"onlineSessions"`
	// LastActive 是服务端最近一次观测到本账号有流量的时间（Unix 秒，0 表示从未）。
	// 服务端用它替代内核不提供的「在线数」，见 ctl.User.LastActive 的说明。
	LastActive  int64 `json:"lastActive"`
	CollectedAt int64 `json:"collectedAt"`
}

// NewAPIClient 构造控制面客户端。
//
// 这里刻意**不做**「用户填了 IP 就跳过证书校验」这种降级。
// 这条连接承载的是账号密码、令牌与连接身份，是整套系统里唯一传输明文凭据的通道；
// 一旦不校验证书，同网段的攻击者用一张自签证书就能把它们全部拿走，
// 还能顺手返回伪造的连接参数把流量引到自己的服务器。
//
// 而服务端证书是签给域名的，填 IP 必然校验失败——所以正确的做法是
// 用 ValidateHost 提前拒绝 IP，让用户改填域名（这也与「连接只允许域名」的设计一致）。
func NewAPIClient(host string, port int) *APIClient {
	return &APIClient{
		base: fmt.Sprintf("https://%s", net.JoinHostPort(host, strconv.Itoa(port))),
		hc:   &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{}},
	}
}

// ValidateHost 校验服务器地址是否可用。
//
// 只接受域名：证书是按域名签发的，用 IP 连必然校验失败，
// 而绕过校验就等于把凭据交给同网段的任何攻击者。
func ValidateHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return fmt.Errorf("请填写服务器域名")
	}
	if net.ParseIP(h) != nil {
		return fmt.Errorf("请填写域名而不是 IP 地址：证书是按域名签发的，用 IP 连接无法验证服务器身份")
	}
	if !strings.Contains(h, ".") {
		return fmt.Errorf("服务器地址看起来不像域名：%s", h)
	}
	return nil
}

// BaseURL 返回控制面根地址，用于界面展示。
func (c *APIClient) BaseURL() string { return c.base }

func (c *APIClient) do(method, path, token string, body any, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("无法连接服务端: %w", err)
	}
	defer resp.Body.Close()

	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return fmt.Errorf("服务端返回异常（HTTP %d）", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("服务端返回 HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Login 用账号密码换取令牌与连接参数。
func (c *APIClient) Login(username, password string) (*LoginResult, error) {
	var out LoginResult
	if err := c.do(http.MethodPost, "/api/v1/login", "",
		map[string]string{"username": username, "password": password}, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, fmt.Errorf("服务端未返回令牌")
	}
	return &out, nil
}

// Traffic 查询当前账号的流量。
func (c *APIClient) Traffic(token string) (*Traffic, error) {
	var out Traffic
	if err := c.do(http.MethodGet, "/api/v1/traffic", token, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChangePassword 修改密码。服务端会同时更换该账号的连接身份，
// 因此调用成功后必须重新登录才能拿到新的连接参数。
func (c *APIClient) ChangePassword(token, oldPassword, newPassword string) error {
	return c.do(http.MethodPost, "/api/v1/password", token,
		map[string]string{"oldPassword": oldPassword, "newPassword": newPassword}, nil)
}

// Health 用于登录前探测服务端是否可达。
func (c *APIClient) Health() error {
	return c.do(http.MethodGet, "/api/v1/health", "", nil, nil)
}
