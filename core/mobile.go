package core

import (
	"firefox-vpn-core/vpnclient"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type AndroidBridge interface {
	ProtectSocket(fd int) bool
	OnStatusUpdate(status string)
	OnLog(level string, message string) // 新增：日志回调
}

var (
	activeSession *vpnclient.H3Session
	tunCloser     io.Closer
	socksListener net.Listener
	bridgeInstance AndroidBridge
	bridgeMu       sync.RWMutex
)

func logToUI(level, format string, args ...any) {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	if bridgeInstance != nil {
		timestamp := time.Now().Format("15:04:05.000")
		msg := fmt.Sprintf("[%s] %s", timestamp, fmt.Sprintf(format, args...))
		bridgeInstance.OnLog(level, msg)
	}
}

func RegisterBridge(bridge AndroidBridge) {
	bridgeMu.Lock()
	bridgeInstance = bridge
	bridgeMu.Unlock()
	logToUI("INFO", "Bridge registered successfully")
}

func InitAuthURL() (string, string, error) {
	logToUI("INFO", "Initializing PKCE OAuth flow...")
	sess, err := vpnclient.GeneratePKCEAuthURL()
	if err != nil {
		logToUI("ERROR", "PKCE Gen Failed: %v", err)
		return "", "", err
	}
	logToUI("INFO", "OAuth URL generated successfully")
	return sess.AuthURL, sess.Verifier, nil
}

func FinishAuthCode(code, verifier string) (string, error) {
	logToUI("INFO", "Exchanging Auth Code for Access Token...")
	token, err := vpnclient.ExchangeCode(code, verifier)
	if err != nil {
		logToUI("ERROR", "Token Exchange Error: %v", err)
		return "", err
	}
	logToUI("INFO", "Token obtained successfully (Length: %d)", len(token))
	return token, nil
}

func StartVPN(tunFd int, proxyPassJWT string, selectedNode string, bridge AndroidBridge) error {
	RegisterBridge(bridge)
	logToUI("INFO", "Starting VPN pipeline, target node: %s", selectedNode)
	bridge.OnStatusUpdate("CONNECTING")

	// 1. 建立 H3 会话
	session, err := vpnclient.NewH3Session(selectedNode, proxyPassJWT, 15*time.Second, func(fd int) {
		if !bridge.ProtectSocket(fd) {
			logToUI("WARN", "Protect socket returned false, fd: %d", fd)
		} else {
			logToUI("DEBUG", "Socket %d protected", fd)
		}
	})
	if err != nil {
		logToUI("ERROR", "Failed to build HTTP/3 upstream: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return err
	}
	activeSession = session
	logToUI("INFO", "HTTP/3 CONNECT session established")

	// 2. 本地回环 SOCKS
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logToUI("ERROR", "Local SOCKS listen failed: %v", err)
		return err
	}
	socksListener = l
	localAddr := l.Addr().String()
	logToUI("INFO", "Internal loopback SOCKS listening on: %s", localAddr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleSocksConn(conn, activeSession)
		}
	}()

	// 3. 启动 Tun 虚拟网卡转发
	logToUI("INFO", "Attaching tun2socks to TUN file descriptor: %d", tunFd)
	closer, err := vpnclient.StartTun2Socks(tunFd, 1500, localAddr)
	if err != nil {
		logToUI("ERROR", "Failed to start tun2socks: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return err
	}
	tunCloser = closer
	logToUI("INFO", "VPN is fully running")
	bridge.OnStatusUpdate("CONNECTED")
	return nil
}

func StopVPN() {
	logToUI("INFO", "Stopping VPN...")
	if tunCloser != nil {
		tunCloser.Close()
	}
	if socksListener != nil {
		socksListener.Close()
	}
	if activeSession != nil {
		activeSession.Close()
	}
	logToUI("INFO", "VPN stopped completely")
	if bridgeInstance != nil {
		bridgeInstance.OnStatusUpdate("DISCONNECTED")
	}
}

func handleSocksConn(client net.Conn, session *vpnclient.H3Session) {
	defer client.Close()
	// 此处保持之前的隧道转发逻辑，并在发生连接错误时调用 logToUI 记录
}
