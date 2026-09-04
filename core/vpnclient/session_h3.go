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
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy port %s: %w", portStr, err)
	}

	// 核心修复：优先通过 DoH 获取未被国内运营商污染/拦截的真实 IP，彻底解决 "no such host"
	cleanIPStr := ResolveCleanIP(host)
	targetIP := net.ParseIP(cleanIPStr)
	if targetIP == nil {
		// 如果 DoH 没直接返回纯 IP，退回使用系统底层解析
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s failed: %w", host, err)
		}
		targetIP = ips[0]
	}

	// 1. 创建本地 UDP 套接字
	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp failed: %w", err)
	}

	// 2. 执行 Android VpnService.protect() 防回环（生命线）
	if protectFn != nil {
		rawConn, err := uc.SyscallConn()
		if err == nil {
			_ = rawConn.Control(func(fd uintptr) {
				protectFn(int(fd))
			})
		}
	}

	tlsCfg := &tls.Config{
		ServerName: host, // TLS SNI 依然保留节点域名，保证证书验证通过
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	quicCfg := &quic.Config{
		KeepAlivePeriod:   30 * time.Second,
		InitialPacketSize: 1200, // 抗移动网络小 MTU 丢包
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 3. 目标地址使用真实解析出来的 targetIP
	udpRemote := &net.UDPAddr{IP: targetIP, Port: port}
	qConn, err := quic.DialEarly(ctx, uc, udpRemote, tlsCfg, quicCfg)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("quic dial early to %s (%s): %w", host, targetIP.String(), err)
	}

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
