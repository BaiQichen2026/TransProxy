package core

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
)

// ---------- 假客户端 ----------
//
// hyclient.Client 是接口，所以整套 SOCKS5 入口可以脱离真实服务器测。
// 这段代码是通道B里最容易悄悄写错的部分（握手字节、地址编码、UDP 封装），
// 而错了的表现是「连上了但打不开网页」，所以必须有真实往返的测试兜住。

type fakeClient struct {
	tcpConn net.Conn
	udpConn *fakeHyUDP
}

func (f *fakeClient) TCP(string) (net.Conn, error) { return f.tcpConn, nil }
func (f *fakeClient) UDP() (hyclient.HyUDPConn, error) {
	if f.udpConn == nil {
		return nil, io.EOF
	}
	return f.udpConn, nil
}
func (f *fakeClient) Close() error { return nil }

type udpSend struct {
	data string
	addr string
}

type fakeHyUDP struct {
	sent chan udpSend
	recv chan udpSend
	done chan struct{}
}

func newFakeHyUDP() *fakeHyUDP {
	return &fakeHyUDP{
		sent: make(chan udpSend, 8),
		recv: make(chan udpSend, 8),
		done: make(chan struct{}),
	}
}

func (u *fakeHyUDP) Send(b []byte, addr string) error {
	u.sent <- udpSend{data: string(b), addr: addr}
	return nil
}

func (u *fakeHyUDP) Receive() ([]byte, string, error) {
	select {
	case m := <-u.recv:
		return []byte(m.data), m.addr, nil
	case <-u.done:
		return nil, "", io.EOF
	}
}

func (u *fakeHyUDP) Close() error {
	select {
	case <-u.done:
	default:
		close(u.done)
	}
	return nil
}

func startTestSocks(t *testing.T, c hyclient.Client) *socks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &socks5Server{client: c, ln: ln}
	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

func dialSocks(t *testing.T, srv *socks5Server) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", srv.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// 方法协商必须回 noauth（0x00）。回别的值会让内核改用我们没实现的认证方式，
// 现象是内核侧直接报「SOCKS 握手失败」。
func TestSocksGreetingPicksNoAuth(t *testing.T) {
	srv := startTestSocks(t, &fakeClient{})
	c := dialSocks(t, srv)

	if _, err := c.Write([]byte{5, 2, 0, 2}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("协商应答应为 [5 0]，实际 %v", reply)
	}
}

// CONNECT 要走通：应答成功，且之后两个方向的数据都能原样穿过。
func TestSocksConnectRelaysData(t *testing.T) {
	remote, fakeSide := net.Pipe()
	defer remote.Close()
	fake := &fakeClient{tcpConn: fakeSide}
	srv := startTestSocks(t, fake)
	c := dialSocks(t, srv)

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	mustRead(t, c, 2)

	// 目标是域名形式，和内核实际发出的请求一致
	host := "example.com"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x01, 0xbb) // 443
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("CONNECT 应成功（REP=0），实际 %d", reply[1])
	}

	// 客户端 → 远端。
	// 注意方向：fakeClient 返回的是 fakeSide，服务端从 SOCKS 连接读到数据后
	// 写进 fakeSide，所以要读的是另一头 remote。
	go func() { _, _ = c.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(remote, buf); err != nil {
		t.Fatalf("远端没收到数据：%v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("远端收到的内容不对：%q", buf)
	}

	// 远端 → 客户端
	go func() { _, _ = remote.Write([]byte("pong")) }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("客户端没收到回包：%v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("客户端收到的内容不对：%q", buf)
	}
}

// CONNECT 失败时必须回一个明确的错误码，而不是让内核干等。
func TestSocksConnectFailureRepliesError(t *testing.T) {
	srv := startTestSocks(t, &failingTCPClient{})
	c := dialSocks(t, srv)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	mustRead(t, c, 2)

	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0x00, 0x50}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] == 0 {
		t.Fatal("连接失败时应答却是成功")
	}
}

type failingTCPClient struct{}

func (f *failingTCPClient) TCP(string) (net.Conn, error) { return nil, io.ErrUnexpectedEOF }
func (f *failingTCPClient) UDP() (hyclient.HyUDPConn, error) {
	return nil, io.EOF
}
func (f *failingTCPClient) Close() error { return nil }

// 不支持的命令要回 0x07（command not supported）。
func TestSocksUnsupportedCommand(t *testing.T) {
	srv := startTestSocks(t, &fakeClient{})
	c := dialSocks(t, srv)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	mustRead(t, c, 2)

	// BIND = 0x02
	req := []byte{5, 2, 0, 1, 127, 0, 0, 1, 0x00, 0x50}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 7 {
		t.Fatalf("不支持的命令应回 7，实际 %d", reply[1])
	}
}

// UDP ASSOCIATE 的完整往返：内核发来的 UDP 报文要交给 hysteria 客户端，
// 远端回来的数据要重新封成 SOCKS5 UDP 报文送给内核。
func TestSocksUDPAssociateRelaysDatagrams(t *testing.T) {
	fakeUDP := newFakeHyUDP()
	fake := &fakeClient{udpConn: fakeUDP}
	srv := startTestSocks(t, fake)

	// 1) 建立 UDP 关联，拿到中继地址
	c := dialSocks(t, srv)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	mustRead(t, c, 2)
	// cmd=3（UDP ASSOCIATE），地址填 0.0.0.0:0 —— 内核就是这么发的
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("UDP ASSOCIATE 应成功，实际 REP=%d", reply[1])
	}
	relay := &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(binary.BigEndian.Uint16(reply[8:10])),
	}

	// 2) 内核 → 中继：应转成 hysteria 的 Send
	client, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := []byte("query")
	pkt, ok := buildSocksUDP("example.com:53", payload)
	if !ok {
		t.Fatal("构造 UDP 报文失败")
	}
	if _, err := client.Write(pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-fakeUDP.sent:
		if got.data != "query" || got.addr != "example.com:53" {
			t.Fatalf("转发给 hysteria 的内容不对：%+v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hysteria 客户端没收到 UDP 数据")
	}

	// 3) 远端 → 中继：应重新封装后回到内核
	fakeUDP.recv <- udpSend{data: "answer", addr: "8.8.8.8:53"}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("内核侧没收到回包：%v", err)
	}
	host, port, got, ok := parseSocksUDP(buf[:n])
	if !ok {
		t.Fatalf("回包不是合法的 SOCKS5 UDP 报文：%v", buf[:n])
	}
	if host != "8.8.8.8" || port != 53 || string(got) != "answer" {
		t.Fatalf("回包内容不对：host=%s port=%d data=%q", host, port, got)
	}
}

// ---------- 线格式 ----------

func TestParseSocksUDPFormats(t *testing.T) {
	// IPv4
	v4, _ := buildSocksUDP("1.2.3.4:443", []byte("x"))
	h, p, d, ok := parseSocksUDP(v4)
	if !ok || h != "1.2.3.4" || p != 443 || string(d) != "x" {
		t.Fatalf("IPv4 报文解析不对：%s %d %q %v", h, p, d, ok)
	}
	// 域名
	dom, _ := buildSocksUDP("example.com:53", []byte("y"))
	h, p, d, ok = parseSocksUDP(dom)
	if !ok || h != "example.com" || p != 53 || string(d) != "y" {
		t.Fatalf("域名报文解析不对：%s %d %q %v", h, p, d, ok)
	}
	// IPv6
	v6, _ := buildSocksUDP("[2001:db8::1]:8443", []byte("z"))
	h, p, d, ok = parseSocksUDP(v6)
	if !ok || h != "2001:db8::1" || p != 8443 || string(d) != "z" {
		t.Fatalf("IPv6 报文解析不对：%s %d %q %v", h, p, d, ok)
	}
}

func TestParseSocksUDPRejectsBadPackets(t *testing.T) {
	good, _ := buildSocksUDP("1.2.3.4:443", []byte("x"))

	// 太短
	if _, _, _, ok := parseSocksUDP([]byte{0, 0, 0}); ok {
		t.Fatal("过短的报文不该被接受")
	}
	// RSV 非 0
	bad := append([]byte(nil), good...)
	bad[0] = 1
	if _, _, _, ok := parseSocksUDP(bad); ok {
		t.Fatal("RSV 非 0 的报文不该被接受")
	}
	// FRAG 非 0：我们不做重组，丢弃比错误拼接安全
	bad = append([]byte(nil), good...)
	bad[2] = 1
	if _, _, _, ok := parseSocksUDP(bad); ok {
		t.Fatal("分片报文不该被接受")
	}
	// 地址类型不支持
	bad = append([]byte(nil), good...)
	bad[3] = 9
	if _, _, _, ok := parseSocksUDP(bad); ok {
		t.Fatal("未知地址类型不该被接受")
	}
	// 域名长度超出剩余字节
	trunc := []byte{0, 0, 0, 3, 10, 'a', 'b'}
	if _, _, _, ok := parseSocksUDP(trunc); ok {
		t.Fatal("截断的域名报文不该被接受")
	}
}

func TestReadSocksAddr(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"IPv4", []byte{1, 1, 2, 3, 4}, "1.2.3.4"},
		{"域名", append([]byte{3, 3}, []byte("abc")...), "abc"},
		{"IPv6", append([]byte{4}, net.ParseIP("2001:db8::1").To16()...), "2001:db8::1"},
	}
	for _, c := range tests {
		// 跳过 ATYP 本身：readSocksAddr 拿到的是 ATYP 之后的地址字节。
		got, err := readSocksAddr(strings.NewReader(string(c.in[1:])), c.in[0])
		if err != nil {
			t.Fatalf("%s：%v", c.name, err)
		}
		if got != c.want {
			t.Fatalf("%s：得到 %q，期望 %q", c.name, got, c.want)
		}
	}
	if _, err := readSocksAddr(strings.NewReader("\x09"), 9); err == nil {
		t.Fatal("未知地址类型应当报错")
	}
}

func mustRead(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatalf("读取 %d 字节失败：%v", n, err)
	}
	return b
}
