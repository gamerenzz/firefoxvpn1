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

type DirectLoginResult struct {
	SessionToken string
	Need2FA      bool
	AccessToken  string
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

// StartEngine 自动获取真实节点、换取 ProxyPass 并连接
func StartEngine(accessToken string, bridge AndroidBridge) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			logToUI("FATAL", "Recovered from panic: %v", r)
		}
	}()

	RegisterBridge(bridge)
	bridge.OnStatusUpdate("CONNECTING")

	// 1. 从 Mozilla 官方拉取最新真实节点列表
	logToUI("INFO", "Fetching official Fastly nodes from Mozilla Remote Settings...")
	endpoints, err := vpnclient.FetchRealServerEndpoints()
	if err != nil {
		logToUI("WARN", "Fetch serverlist failed: %v. Using fallback node.", err)
		// 备用真实 Fastly 节点 (带正确的端口 2499)
		endpoints = []string{"rjtf770.m1.fastly-masque.net:2499", "lfpb115.m1.fastly-masque.net:2499"}
	} else {
		logToUI("INFO", "Fetched %d official VPN nodes successfully", len(endpoints))
	}

	// 2. 并发探测最快节点 (取前 10 个测试)
	testCandidates := endpoints
	if len(testCandidates) > 10 {
		testCandidates = testCandidates[:10]
	}
	logToUI("INFO", "Probing lowest latency node...")
	bestNode := vpnclient.ProbeFastestNode(testCandidates, 2*time.Second, func(fd int) {
		bridge.ProtectSocket(fd)
	})
	if bestNode == "" {
		bestNode = endpoints[0]
	}
	logToUI("INFO", "Selected best node: %s", bestNode)

	// 3. 用 AccessToken 向 Guardian 换取 Proxy Pass JWT
	logToUI("INFO", "Fetching Proxy Pass JWT from Mozilla Guardian...")
	proxyPassJWT, err := vpnclient.GetProxyPassWithToken(accessToken)
	if err != nil {
		logToUI("ERROR", "Fetch Proxy Pass failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	logToUI("INFO", "Proxy Pass obtained! Connecting HTTP/3 tunnel to %s...", bestNode)

	// 4. 建立底层 HTTP/3 隧道
	session, err := vpnclient.NewH3Session(bestNode, proxyPassJWT, 15*time.Second, func(fd int) {
		bridge.ProtectSocket(fd)
	})
	if err != nil {
		logToUI("ERROR", "HTTP/3 Upstream connect failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	activeSession = session
	logToUI("INFO", "HTTP/3 MASQUE tunnel established successfully!")

	// 5. 启动本地代理
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
