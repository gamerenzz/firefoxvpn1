package vpnclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type H3Session struct {
	rt        *http3.Transport
	conn      quic.EarlyConnection
	udpConn   *net.UDPConn
	proxyHost string
	token     string
	timeout   time.Duration
}

func NewH3Session(proxyAddr, token string, timeout time.Duration, protectFn func(fd int)) (*H3Session, error) {
	host, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %s: %w", proxyAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 443
	}

	// 1. 防 DNS 污染安全解析真实 IP
	cleanIPStr := ResolveCleanIP(host)
	targetIP := net.ParseIP(cleanIPStr)
	if targetIP == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s failed: %w", host, err)
		}
		targetIP = ips[0]
	}

	// 2. 创建本地 UDP 套接字
	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %w", err)
	}

	// 3. 核心：执行 Android VpnService.protect() 保证底层流量不产生回环死循环
	if protectFn != nil {
		rawConn, err := uc.SyscallConn()
		if err == nil {
			_ = rawConn.Control(func(fd uintptr) {
				protectFn(int(fd))
			})
		}
	}

	tlsCfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	quicCfg := &quic.Config{
		KeepAlivePeriod:   30 * time.Second,
		InitialPacketSize: 1200, // 抗移动网络小 MTU 丢包
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 4. 发起 QUIC 0-RTT 握手（首选目标端口，如果非 443 端口受阻，自动回退到 443 端口尝试）
	udpRemote := &net.UDPAddr{IP: targetIP, Port: port}
	qConn, err := quic.DialEarly(ctx, uc, udpRemote, tlsCfg, quicCfg)
	if err != nil {
		// 容错回退：部分节点在公网标准开放的是 443 端口
		if port != 443 {
			udpRemote443 := &net.UDPAddr{IP: targetIP, Port: 443}
			qConn, err = quic.DialEarly(ctx, uc, udpRemote443, tlsCfg, quicCfg)
		}
		if err != nil {
			uc.Close()
			return nil, fmt.Errorf("quic dial to %s (ip: %s) failed: %w", proxyAddr, targetIP.String(), err)
		}
	}

	// 5. 组装支持标准 HTTP/3 CONNECT 的 RoundTripper
	rt := &http3.Transport{
		Dial: func(_ context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return qConn, nil
		},
	}

	return &H3Session{
		rt:        rt,
		conn:      qConn,
		udpConn:   uc,
		proxyHost: proxyAddr,
		token:     token,
		timeout:   timeout,
	}, nil
}

func (s *H3Session) OpenTunnel(authority string) (io.ReadWriteCloser, error) {
	reqBuf := NewTunnelWriteBuffer(DefaultBufferSize)
	req, err := http.NewRequest(http.MethodConnect, "https://"+authority, reqBuf)
	if err != nil {
		return nil, err
	}
	req.Host = authority
	req.URL.Host = s.proxyHost
	req.Header.Set("Proxy-Authorization", "Bearer "+s.token)

	resp, err := s.rt.RoundTrip(req)
	if err != nil {
		reqBuf.FailRead(io.ErrClosedPipe)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		reqBuf.FailRead(io.ErrClosedPipe)
		return nil, fmt.Errorf("upstream connect returned: %d", resp.StatusCode)
	}

	return &TunnelStream{
		reader: resp.Body,
		writer: reqBuf,
	}, nil
}

func (s *H3Session) Close() error {
	if s.rt != nil {
		s.rt.Close()
	}
	if s.conn != nil {
		_ = s.conn.CloseWithError(0, "")
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	return nil
}

type TunnelStream struct {
	reader io.ReadCloser
	writer *TunnelWriteBuffer
}

func (t *TunnelStream) Read(p []byte) (int, error)  { return t.reader.Read(p) }
func (t *TunnelStream) Write(p []byte) (int, error) { return t.writer.Write(p) }
func (t *TunnelStream) Close() error {
	t.writer.Close()
	return t.reader.Close()
}
