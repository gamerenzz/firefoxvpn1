package core

import (
	"encoding/json"
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

type DirectLoginResult struct {
	SessionToken string
	Need2FA      bool
	AccessToken  string
}

type NodeInfo struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
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

func LoginWithPassword(email, password string) (*DirectLoginResult, error) {
	logToUI("INFO", "Logging in with official Mozilla VPN client ID...")
	resp, err := vpnclient.DirectLogin(email, password)
	if err != nil {
		logToUI("ERROR", "Login failed: %v", err)
		return nil, err
	}

	if !resp.Verified {
		logToUI("WARN", "Account requires email 2FA verification")
		return &DirectLoginResult{
			SessionToken: resp.SessionToken,
			Need2FA:      true,
		}, nil
	}

	logToUI("INFO", "Exchanging session token for VPN AccessToken...")
	token, err := vpnclient.ExchangeSessionToOAuthToken(resp.SessionToken)
	if err != nil {
		logToUI("ERROR", "Exchange OAuth token failed: %v", err)
		return nil, err
	}

	logToUI("INFO", "Login SUCCESS! Token obtained.")
	return &DirectLoginResult{
		AccessToken: token,
		Need2FA:     false,
	}, nil
}

func Submit2FACode(sessionToken, code string) (string, error) {
	logToUI("INFO", "Submitting 2FA verification code...")
	if err := vpnclient.VerifySessionCode(sessionToken, code); err != nil {
		logToUI("ERROR", "Verify code failed: %v", err)
		return "", err
	}
	logToUI("INFO", "Code verified! Exchanging for VPN AccessToken...")
	token, err := vpnclient.ExchangeSessionToOAuthToken(sessionToken)
	if err != nil {
		logToUI("ERROR", "Exchange token failed: %v", err)
		return "", err
	}
	logToUI("INFO", "2FA Authentication SUCCESS!")
	return token, nil
}

// FetchNodesJSON 返回 100% 具有全球公网权威 DNS 解析的官方主力节点
func FetchNodesJSON() string {
	list := []NodeInfo{
		{Name: "🇯🇵 日本东京 (jp0.vpn.mozilla.org:443)", Addr: "jp0.vpn.mozilla.org:443"},
		{Name: "🇸🇬 新加坡 (sg0.vpn.mozilla.org:443)", Addr: "sg0.vpn.mozilla.org:443"},
		{Name: "🇺🇸 美国西海岸 (us0.vpn.mozilla.org:443)", Addr: "us0.vpn.mozilla.org:443"},
		{Name: "🇩🇪 德国法兰克福 (de0.vpn.mozilla.org:443)", Addr: "de0.vpn.mozilla.org:443"},
		{Name: "🇬🇧 英国伦敦 (uk0.vpn.mozilla.org:443)", Addr: "uk0.vpn.mozilla.org:443"},
	}

	data, _ := json.Marshal(list)
	return string(data)
}

// TestNodeDelay 测试指定节点的连通性与往返延迟
func TestNodeDelay(nodeAddr string) int64 {
	return vpnclient.PingSingleNode(nodeAddr, 2500*time.Millisecond, func(fd int) {
		bridgeMu.RLock()
		if bridgeInstance != nil {
			bridgeInstance.ProtectSocket(fd)
		}
		bridgeMu.RUnlock()
	})
}

// StartEngine 明确连接用户手动指定的公网节点
func StartEngine(targetNode string, token string, bridge AndroidBridge) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			logToUI("FATAL", "Recovered from panic: %v", r)
		}
	}()

	RegisterBridge(bridge)
	bridge.OnStatusUpdate("CONNECTING")

	protectFunc := func(fd int) {
		bridge.ProtectSocket(fd)
	}

	if targetNode == "" {
		targetNode = "jp0.vpn.mozilla.org:443"
	}

	logToUI("INFO", "Establishing HTTP/3 tunnel to: %s", targetNode)

	// 发起 HTTP/3 握手
	session, err := vpnclient.NewH3Session(targetNode, token, 15*time.Second, protectFunc)
	if err != nil {
		logToUI("ERROR", "HTTP/3 Upstream connect failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	activeSession = session
	logToUI("INFO", "HTTP/3 MASQUE tunnel established successfully!")

	// 启动本地回环 SOCKS5
	br, localAddr, err := vpnclient.StartLocalSocksBridge(session)
	if err != nil {
		logToUI("ERROR", "Local bridge failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	localBridge = br

	logToUI("INFO", "VPN is READY! Local SOCKS5 running on %s", localAddr)
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
