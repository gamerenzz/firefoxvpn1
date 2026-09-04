package core

import (
	"firefox-vpn-core/vpnclient"
	"fmt"
	"io"
	"net"
	"time"
)

// AndroidBridge 由 Android 实现的回调接口
type AndroidBridge interface {
	ProtectSocket(fd int) bool
	OnStatusUpdate(status string)
}

var (
	activeSession *vpnclient.H3Session
	tunCloser     io.Closer
	socksListener net.Listener
)

// InitAuthURL 生成授权页面，让 Android 打开
func InitAuthURL() (string, string, error) {
	sess, err := vpnclient.GeneratePKCEAuthURL()
	if err != nil {
		return "", "", err
	}
	return sess.AuthURL, sess.Verifier, nil
}

// FinishAuthCode 授权码换 Token
func FinishAuthCode(code, verifier string) (string, error) {
	return vpnclient.ExchangeCode(code, verifier)
}

// StartVPN 启动底层引擎并接管 TUN 设备
func StartVPN(tunFd int, proxyPassJWT string, selectedNode string, bridge AndroidBridge) error {
	bridge.OnStatusUpdate("CONNECTING_UPSTREAM")

	// 1. 启动 HTTP/3 隧道，并注入 Socket 保护
	session, err := vpnclient.NewH3Session(selectedNode, proxyPassJWT, 15*time.Second, func(fd int) {
		bridge.ProtectSocket(fd)
	})
	if err != nil {
		return fmt.Errorf("h3 dial: %w", err)
	}
	activeSession = session

	// 2. 本地回环启动极简 SOCKS5 承载 TUN 流量
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	socksListener = l
	localAddr := l.Addr().String()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleSocksConn(conn, activeSession)
		}
	}()

	// 3. 启动 tun2socks
	tunCloser = vpnclient.StartTun2Socks(tunFd, 1500, localAddr)
	bridge.OnStatusUpdate("CONNECTED")
	return nil
}

// StopVPN 断开停止
func StopVPN() {
	if tunCloser != nil {
		tunCloser.Close()
	}
	if socksListener != nil {
		socksListener.Close()
	}
	if activeSession != nil {
		activeSession.Close()
	}
}

func handleSocksConn(client net.Conn, session *vpnclient.H3Session) {
	defer client.Close()
	// 标准 SOCKS5 握手并直接向 H3 Session 发起 CONNECT
	// 这里通过 RingBuffer 进行双向流量拷贝
	// 略：常规 3 步握手协议处理 (参考 11.md main.go socksServer)
}
