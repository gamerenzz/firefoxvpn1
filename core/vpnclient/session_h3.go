package vpnclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type H3Session struct {
	rt        *http3.Transport
	conn      *quic.Conn
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
	port, _ := strconv.Atoi(portStr)

	// 解析 IP
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s failed: %w", host, err)
	}

	// 创建 UDP 并执行 Android VpnService.protect()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}

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

	udpRemote := &net.UDPAddr{IP: ips[0], Port: port}
	qConn, err := quic.Dial(ctx, uc, udpRemote, tlsCfg, quicCfg)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	rt := &http3.Transport{
		Dial: func(_ context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
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
		(*s.conn).CloseWithError(0, "")
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
