package core

import (
	"firefox-vpn-core/vpnclient"
	"fmt"
	"sync"
	"time"
)

type AndroidBridge interface {
	ProtectSocket(fd int) bool
	OnStatusUpdate(status string)
	OnLog(level string, message string)
}

// AuthSessionResult 封装为结构体，完全符合 Gomobile 跨语言规范
type AuthSessionResult struct {
	AuthURL  string
	Verifier string
}

var (
	activeSession  *vpnclient.H3Session
	localBridge    *vpnclient.LocalBridge
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

// InitAuthURL 改为返回 (*AuthSessionResult, error)，100% 兼容 Java
func InitAuthURL() (*AuthSessionResult, error) {
	logToUI("INFO", "Initializing PKCE OAuth flow...")
	sess, err := vpnclient.GeneratePKCEAuthURL()
	if err != nil {
		logToUI("ERROR", "PKCE Gen Failed: %v", err)
		return nil, err
	}
	logToUI("INFO", "OAuth URL generated successfully")
	return &AuthSessionResult{
		AuthURL:  sess.AuthURL,
		Verifier: sess.Verifier,
	}, nil
}

func FinishAuthCode(code, verifier string) (string, error) {
	logToUI("INFO", "Exchanging Auth Code for Access Token...")
	token, err := vpnclient.ExchangeCode(code, verifier)
	if err != nil {
		logToUI("ERROR", "Token Exchange Error: %v", err)
		return "", err
	}
	logToUI("INFO", "Token obtained successfully")
	return token, nil
}

// StartEngine 启动底层 HTTP/3 隧道，并返回绑定的本地回环端口
func StartEngine(proxyPassJWT string, selectedNode string, bridge AndroidBridge) (string, error) {
	RegisterBridge(bridge)
	logToUI("INFO", "Starting H3 MASQUE Engine -> %s", selectedNode)
	bridge.OnStatusUpdate("CONNECTING")

	session, err := vpnclient.NewH3Session(selectedNode, proxyPassJWT, 15*time.Second, func(fd int) {
		bridge.ProtectSocket(fd)
	})
	if err != nil {
		logToUI("ERROR", "H3 Connection Failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	activeSession = session

	br, localAddr, err := vpnclient.StartLocalSocksBridge(session)
	if err != nil {
		logToUI("ERROR", "Local SOCKS Bridge Failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	localBridge = br

	logToUI("INFO", "VPN Core Online, SOCKS5 at: %s", localAddr)
	bridge.OnStatusUpdate("CONNECTED")
	return localAddr, nil
}

func StopEngine() {
	logToUI("INFO", "Stopping Core Engine...")
	if localBridge != nil {
		localBridge.Close()
	}
	if activeSession != nil {
		activeSession.Close()
	}
	logToUI("INFO", "Core Engine stopped")
	if bridgeInstance != nil {
		bridgeInstance.OnStatusUpdate("DISCONNECTED")
	}
}
