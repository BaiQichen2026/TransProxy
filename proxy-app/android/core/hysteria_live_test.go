package core

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// 通道B 的联网集成测试。
//
// 默认跳过：它要连真实的服务器、用真实的账号，不适合放进普通 `go test`。
// 需要时这样跑（账号可以是临时建的，测完删掉）：
//
//	HY_TEST_USER=xxx HY_TEST_PASS=yyyy go test -run TestLiveHysteria -v ./...
//
// 为什么必须有它：单元测试用的是假客户端，验的是 SOCKS5 那一层；
// 而「混淆密钥有没有配对」「SNI 对不对」「认证能不能过」这三件事
// 只有连真服务器才能证明，错了的表现是「连上了但什么都打不开」——
// 恰恰是最难从现象反推原因的那类故障。

type liveParams struct {
	Address         string `json:"address"`
	Port            int    `json:"port"`
	SNI             string `json:"sni"`
	HysteriaEnabled bool   `json:"hysteriaEnabled"`
	HysteriaPort    int    `json:"hysteriaPort"`
	HysteriaObfs    string `json:"hysteriaObfs"`
}

func liveLogin(t *testing.T, host string, port int, user, pass string) liveParams {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	cli := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			// 服务端用的是正规证书，走标准校验；域名与证书匹配。
			TLSClientConfig: &tls.Config{ServerName: host},
		},
	}
	resp, err := cli.Post(fmt.Sprintf("https://%s:%d/api/v1/login", host, port),
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("登录失败：%v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("登录返回 %d：%s", resp.StatusCode, raw)
	}
	var out struct {
		Params liveParams `json:"params"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("登录响应解析失败：%v", err)
	}
	return out.Params
}

// socksConnect 走一遍 SOCKS5 的 CONNECT 握手，返回已建立连接的 net.Conn。
func socksConnect(t *testing.T, proxy string, host string, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 10*time.Second)
	if err != nil {
		t.Fatalf("连不上本机 SOCKS 入口：%v", err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if r := mustRead(t, c, 2); r[0] != 5 || r[1] != 0 {
		t.Fatalf("方法协商失败：%v", r)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := mustRead(t, c, 10)
	if rep[1] != 0 {
		t.Fatalf("CONNECT 被拒绝，REP=%d", rep[1])
	}
	return c
}

// socksUDPAssociateRaw 建立 UDP 关联，返回 (TCP 保活连接, 中继地址)。
// 失败时返回 nil，由调用方决定怎么处理（重试还是直接失败）。
func socksUDPAssociateRaw(proxy string) (net.Conn, *net.UDPAddr) {
	c, err := net.DialTimeout("tcp", proxy, 10*time.Second)
	if err != nil {
		return nil, nil
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		_ = c.Close()
		return nil, nil
	}
	neg := make([]byte, 2)
	if _, err := io.ReadFull(c, neg); err != nil || neg[1] != 0 {
		_ = c.Close()
		return nil, nil
	}
	if _, err := c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = c.Close()
		return nil, nil
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0 {
		_ = c.Close()
		return nil, nil
	}
	return c, &net.UDPAddr{
		IP:   net.IPv4(rep[4], rep[5], rep[6], rep[7]),
		Port: int(binary.BigEndian.Uint16(rep[8:10])),
	}
}

func TestLiveHysteriaTunnel(t *testing.T) {
	user := os.Getenv("HY_TEST_USER")
	pass := os.Getenv("HY_TEST_PASS")
	if user == "" || pass == "" {
		t.Skip("未设置 HY_TEST_USER / HY_TEST_PASS，跳过联网测试")
	}
	const host = "proxy.example.com"
	const apiPort = 8443
	const socksPort = 17902

	p := liveLogin(t, host, apiPort, user, pass)
	if !p.HysteriaEnabled || p.HysteriaPort == 0 || p.HysteriaObfs == "" {
		t.Fatalf("服务端没有下发可用的通道B 参数：%+v", p)
	}
	t.Logf("拿到通道B 参数：端口=%d 混淆长度=%d，TLS 服务器名用入口域名 %s",
		p.HysteriaPort, len(p.HysteriaObfs), p.Address)

	// TLS 服务器名用的是**入口域名**（证书上的域名），不是 p.SNI。
	// p.SNI 是 REALITY 借用的伪装站点，与 hysteria 的证书无关。
	if err := StartHysteria(host, p.HysteriaPort, p.Address,
		user+":"+pass, p.HysteriaObfs, socksPort); err != nil {
		t.Fatalf("通道B 握手失败：%v", err)
	}
	defer StopHysteria()
	if !HysteriaRunning() {
		t.Fatal("StartHysteria 返回成功但状态不是运行中")
	}

	t.Run("TCP", func(t *testing.T) {
		c := socksConnect(t, fmt.Sprintf("127.0.0.1:%d", socksPort), "example.com", 80)
		defer c.Close()
		if _, err := c.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("读响应失败：%v", err)
		}
		if !strings.HasPrefix(string(buf[:n]), "HTTP/") {
			t.Fatalf("响应不像 HTTP：%q", buf[:n])
		}
		t.Logf("TCP 通了：%q", strings.TrimSpace(string(buf[:n])))
	})

	t.Run("UDP", func(t *testing.T) {
		// DNS 查询 8.8.8.8:53。UDP 走通才说明 hysteria 的 UDP 中继是活的，
		// 也就意味着 QUIC 之类的网站访问不会被卡住。
		//
		// 允许有限次重试：UDP 本来就是丢包不重传的协议，链路上偶尔掉一个包
		// 不该被报成产品缺陷。但每次都打印，全失败仍然判失败——
		// 这样「偶发丢包」与「UDP 真的不通」不会被混为一谈。
		const attempts = 3
		var lastErr error
		for i := 1; i <= attempts; i++ {
			anCount, err := liveDNSQuery(fmt.Sprintf("127.0.0.1:%d", socksPort))
			if err == nil {
				t.Logf("UDP 通了（第 %d 次尝试）：DNS 应答 %d 条", i, anCount)
				return
			}
			lastErr = err
			t.Logf("第 %d 次 UDP 尝试失败：%v", i, err)
		}
		t.Fatalf("%d 次 UDP 尝试全部失败：%v", attempts, lastErr)
	})
}

// liveDNSQuery 通过通道B 的 SOCKS5 入口做一次 UDP DNS 查询，返回答案条数。
func liveDNSQuery(proxy string) (int, error) {
	c, relay := socksUDPAssociateRaw(proxy)
	if c == nil {
		return 0, fmt.Errorf("建立 UDP 关联失败")
	}
	defer c.Close()

	q, err := dnsQueryBytes("example.com")
	if err != nil {
		return 0, err
	}
	pkt, ok := buildSocksUDP("8.8.8.8:53", q)
	if !ok {
		return 0, fmt.Errorf("构造 UDP 报文失败")
	}
	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return 0, err
	}
	defer uc.Close()
	if _, err := uc.Write(pkt); err != nil {
		return 0, err
	}
	_ = uc.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 1500)
	n, err := uc.Read(buf)
	if err != nil {
		return 0, err
	}
	_, _, payload, ok := parseSocksUDP(buf[:n])
	if !ok {
		return 0, fmt.Errorf("回包不是 SOCKS5 UDP 报文")
	}
	if len(payload) < 12 {
		return 0, fmt.Errorf("DNS 响应过短")
	}
	if payload[0] != q[0] || payload[1] != q[1] {
		return 0, fmt.Errorf("DNS 响应 ID 不匹配")
	}
	return int(binary.BigEndian.Uint16(payload[6:8])), nil
}

// dnsQueryBytes 拼一个最小的 A 记录查询。
func dnsQueryBytes(name string) ([]byte, error) {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, part := range strings.Split(name, ".") {
		if len(part) > 63 {
			return nil, fmt.Errorf("域名标签过长：%s", part)
		}
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	b = append(b, 0x00, 0x00, 0x01, 0x00, 0x01)
	return b, nil
}
