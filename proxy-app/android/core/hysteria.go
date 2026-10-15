package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

// 通道B（Hysteria2）在 Android 上的实现。
//
// 与 Windows 端的差别值得说明：Windows 是「旁挂」——由客户端进程拉起一个 hysteria.exe，
// 内核的 proxy 出站指向它监听的 SOCKS 端口；Android 不允许拉起外部进程，
// 所以这里把 hysteria 客户端以库的形式跑在同一进程内，并自己起一个最小 SOCKS5 入口。
//
// 这样做的价值在于：内核看到的形状与 Windows 完全一致（都是一个本机 SOCKS5 出口），
// 于是分流规则、TUN 接管、两条通道的切换逻辑都不用写两套，
// 也就不可能出现「两条通道行为不一致」这类问题。

// DefaultHySocksPort 是通道B在本机监听的 SOCKS5 端口。
// 与通道A的调试端口（17900）刻意错开：两者可能同时存在（例如刚切换完通道）。
const DefaultHySocksPort = 17902

var (
	hyMu     sync.Mutex
	hyCli    hyclient.Client
	hySocks  *socks5Server
	hyActive bool
)

// StartHysteria 启动通道B：先与服务器完成 QUIC 握手与认证，再在本机起 SOCKS5 入口。
//
// serverName 是**服务器证书上的域名**（即连接入口域名），不是 REALITY 的伪装 SNI。
// 这两个值很容易搞混，而且搞混的后果很隐蔽：TLS 会以「服务端内部错误」告终，
// 看起来像是密钥或混淆配错了。真实的坑：把 www.samsung.com 当成 hysteria 的 SNI
// 传进来，握手直接失败。
//
// 刻意在返回前就完成握手，而不是惰性连接：认证失败、UDP 被运营商阻断这类问题，
// 会因此立刻以真实原因暴露在「点连接」的那一刻。若等有流量才连，
// 用户看到的会是「连接成功但什么都打不开」，那是最难排查的一类现象。
func StartHysteria(serverHost string, serverPort int, serverName, auth, obfsPassword string, socksPort int) error {
	hyMu.Lock()
	defer hyMu.Unlock()
	if hyActive {
		return fmt.Errorf("通道B已在运行")
	}
	if serverHost == "" || serverPort <= 0 || serverPort > 65535 {
		return fmt.Errorf("通道B：服务器地址或端口不合法")
	}
	if serverName == "" {
		return fmt.Errorf("通道B：缺少 TLS 服务器名（应是证书上的域名）")
	}
	if auth == "" {
		return fmt.Errorf("通道B：缺少认证信息（账号:密码）")
	}
	if obfsPassword == "" {
		return fmt.Errorf("通道B：缺少混淆密钥")
	}
	if socksPort <= 0 || socksPort > 65535 {
		socksPort = DefaultHySocksPort
	}

	// 服务器地址可能是域名，这里解析成 IP。这不影响伪装：
	// 对外呈现的域名由 TLSConfig.ServerName（即 SNI）决定，与传输层连的是哪个 IP 无关。
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(serverHost, strconv.Itoa(serverPort)))
	if err != nil {
		return fmt.Errorf("通道B：解析服务器地址失败：%w", err)
	}

	cfg := &hyclient.Config{
		ServerAddr: raddr,
		Auth:       auth,
		TLSConfig: hyclient.TLSConfig{
			ServerName: serverName,
		},
		// 混淆必须自己包在 UDP socket 上：服务端配了 salamander，
		// 不包的话第一个包就会被丢弃，现象是「握手一直超时」。
		ConnFactory: &obfsConnFactory{psk: []byte(obfsPassword)},
	}
	c, info, err := hyclient.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("通道B：握手失败：%w", err)
	}
	if !info.UDPEnabled {
		// 服务端没开 UDP 中继只影响 UDP 目标，TCP 照常可用，所以提示而不拒绝。
		appendLog("通道B：服务端未启用 UDP 中继，UDP 目标将不可用")
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))
	if err != nil {
		_ = c.Close()
		return fmt.Errorf("通道B：本机 SOCKS 端口 %d 被占用：%w", socksPort, err)
	}
	srv := &socks5Server{client: c, ln: ln}
	go srv.serve()

	hyCli, hySocks, hyActive = c, srv, true
	appendLog("通道B 已就绪（服务端 %s，本机 SOCKS 127.0.0.1:%d）", raddr, socksPort)
	return nil
}

// StopHysteria 关闭通道B。可重复调用。
func StopHysteria() {
	hyMu.Lock()
	c, srv, was := hyCli, hySocks, hyActive
	hyCli, hySocks, hyActive = nil, nil, false
	hyMu.Unlock()
	if !was {
		return
	}
	if srv != nil {
		srv.Close()
	}
	if c != nil {
		_ = c.Close()
	}
}

// HysteriaRunning 报告通道B是否已启动。
func HysteriaRunning() bool {
	hyMu.Lock()
	defer hyMu.Unlock()
	return hyActive
}

// obfsConnFactory 按 salamander 要求包装底层 UDP socket。
// 每次建连都会调用它（hysteria 在重连时也会走这里）。
type obfsConnFactory struct{ psk []byte }

func (f *obfsConnFactory) New(net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	wrapped, err := obfs.WrapPacketConnSalamander(conn, f.psk)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return wrapped, nil
}

// ---------- 最小 SOCKS5 入口 ----------
//
// 只实现内核真正会用到的两种命令：
//   - CONNECT：走 hysteria 的 TCP 流；
//   - UDP ASSOCIATE：走 hysteria 的 UDP 会话。
//
// 不做认证：它只监听 127.0.0.1，调用方是本进程内的内核，再设一道口令没有意义。
//
// 关于 UDP 的一个前提：UDP 中继是**单消费者**的（只有本机内核会连它），
// 所以全网共用一个中继端口、用一个 hysteria UDP 会话就够了。
// 若将来要对外提供这个 SOCKS 端口，必须改成按会话隔离。
type socks5Server struct {
	client hyclient.Client
	ln     net.Listener

	udpMu   sync.Mutex
	udpLn   net.PacketConn
	udpSess hyclient.HyUDPConn
	udpCli  net.Addr // 最后一个发来 UDP 报文的客户端地址
}

func (s *socks5Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *socks5Server) Close() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.udpMu.Lock()
	ln, sess := s.udpLn, s.udpSess
	s.udpLn, s.udpSess = nil, nil
	s.udpMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if sess != nil {
		_ = sess.Close()
	}
}

func (s *socks5Server) handle(conn net.Conn) {
	defer conn.Close()
	// 协商阶段给一个超时，避免半开连接一直占着 goroutine。
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// 版本与方法协商
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
		return
	}
	// 只回 noauth（0x00）。回别的值会让内核改用我们并不实现的认证方式。
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	// 请求
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != 5 {
		return
	}
	cmd, atyp := req[1], req[3]
	host, err := readSocksAddr(conn, atyp)
	if err != nil {
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))
	_ = conn.SetDeadline(time.Time{})

	switch cmd {
	case 1: // CONNECT
		s.doConnect(conn, net.JoinHostPort(host, strconv.Itoa(port)))
	case 3: // UDP ASSOCIATE
		s.doUDPAssociate(conn)
	default:
		// 命令不支持（BIND 等）
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func (s *socks5Server) doConnect(conn net.Conn, target string) {
	rc, err := s.client.TCP(target)
	if err != nil {
		appendLog("通道B 连接 %s 失败：%v", target, err)
		// 0x05 = connection refused，让内核立刻得到明确失败而不是干等
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer rc.Close()
	// 成功应答。BND.ADDR/PORT 对内核无意义，填 0 即可。
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(rc, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, rc); done <- struct{}{} }()
	// 任一方向结束就收尾：defer 会关掉两端，另一个 goroutine 随之退出。
	<-done
}

func (s *socks5Server) doUDPAssociate(conn net.Conn) {
	relay, err := s.ensureUDPRelay()
	if err != nil {
		appendLog("通道B UDP 中继启动失败：%v", err)
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	la := relay.LocalAddr().(*net.UDPAddr)
	reply := []byte{5, 0, 0, 1}
	reply = append(reply, la.IP.To4()...)
	reply = append(reply, byte(la.Port>>8), byte(la.Port))
	if _, err := conn.Write(reply); err != nil {
		return
	}
	// 这条 TCP 连接是 UDP 关联的存活信号：内核关掉它就意味着关联结束。
	// 内容不解析，读到关闭为止。
	_, _ = io.Copy(io.Discard, conn)
}

func (s *socks5Server) ensureUDPRelay() (net.PacketConn, error) {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if s.udpLn != nil {
		return s.udpLn, nil
	}
	sess, err := s.client.UDP()
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	s.udpSess, s.udpLn = sess, pc
	go s.relayClientToRemote()
	go s.relayRemoteToClient()
	return pc, nil
}

func (s *socks5Server) relayClientToRemote() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.udpLn.ReadFrom(buf)
		if err != nil {
			return
		}
		host, port, payload, ok := parseSocksUDP(buf[:n])
		if !ok {
			continue
		}
		s.udpMu.Lock()
		s.udpCli = from
		sess := s.udpSess
		s.udpMu.Unlock()
		if sess == nil {
			continue
		}
		if err := sess.Send(payload, net.JoinHostPort(host, strconv.Itoa(port))); err != nil {
			appendLog("通道B UDP 发送失败：%v", err)
		}
	}
}

func (s *socks5Server) relayRemoteToClient() {
	for {
		s.udpMu.Lock()
		sess := s.udpSess
		s.udpMu.Unlock()
		if sess == nil {
			return
		}
		data, addr, err := sess.Receive()
		if err != nil {
			return
		}
		// 客户端地址必须在 Receive 返回**之后**再取。
		// 放在阻塞之前取的话，第一条回包会拿着「还没人发过报文」时的 nil 被丢掉——
		// 这正是单元测试抓到的那个 bug。
		s.udpMu.Lock()
		cli, ln := s.udpCli, s.udpLn
		s.udpMu.Unlock()
		if cli == nil || ln == nil {
			// 还没有客户端发过报文，不知道回给谁。
			continue
		}
		pkt, ok := buildSocksUDP(addr, data)
		if !ok {
			continue
		}
		_, _ = ln.WriteTo(pkt, cli)
	}
}

// readSocksAddr 按地址类型读出目标地址。
func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 3: // 域名
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", fmt.Errorf("不支持的地址类型 %d", atyp)
}

// parseSocksUDP 解析 SOCKS5 UDP 报文：RSV(2) FRAG(1) ATYP ADDR PORT DATA。
func parseSocksUDP(b []byte) (host string, port int, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		return "", 0, nil, false
	}
	// FRAG 非 0 表示分片，我们不支持；丢掉比错误拼接安全。
	if b[2] != 0 {
		return "", 0, nil, false
	}
	i := 4
	switch b[3] {
	case 1:
		if len(b) < i+4+2 {
			return "", 0, nil, false
		}
		host = net.IP(b[i : i+4]).String()
		i += 4
	case 4:
		if len(b) < i+16+2 {
			return "", 0, nil, false
		}
		host = net.IP(b[i : i+16]).String()
		i += 16
	case 3:
		if len(b) < i+1 {
			return "", 0, nil, false
		}
		l := int(b[i])
		i++
		if len(b) < i+l+2 {
			return "", 0, nil, false
		}
		host = string(b[i : i+l])
		i += l
	default:
		return "", 0, nil, false
	}
	port = int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	return host, port, b[i:], true
}

// buildSocksUDP 把远端回来的数据封成 SOCKS5 UDP 报文。
func buildSocksUDP(addr string, payload []byte) ([]byte, bool) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, false
	}
	out := make([]byte, 0, 4+len(host)+2+len(payload))
	out = append(out, 0, 0, 0)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 1)
			out = append(out, v4...)
		} else {
			out = append(out, 4)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, false
		}
		out = append(out, 3, byte(len(host)))
		out = append(out, host...)
	}
	out = append(out, byte(port>>8), byte(port))
	out = append(out, payload...)
	return out, true
}
