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

// StartEngine 全新思路：跳过被墙的 Guardian，直接拿 Token 直连最优 Fastly MASQUE 节点！
func StartEngine(token string, bridge AndroidBridge) (string, error) {
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

	// 1. 获取真实候选节点
	logToUI("INFO", "Loading official Fastly nodes...")
	endpoints := vpnclient.FetchRealServerEndpoints(protectFunc)
	logToUI("INFO", "Loaded %d candidate nodes", len(endpoints))

	// 2. 毫秒级竞速选出当前最快节点
	testCandidates := endpoints
	if len(testCandidates) > 5 {
		testCandidates = testCandidates[:5]
	}
	logToUI("INFO", "Probing lowest latency node...")
	bestNode := vpnclient.ProbeFastestNode(testCandidates, 2*time.Second, protectFunc)
	if bestNode == "" {
		bestNode = endpoints[0]
	}
	logToUI("INFO", "Selected best node: %s", bestNode)

	// 3. 核心改变：不再请求任何被阻断的 Guardian！
	// 直接将我们手头合法的官方 Token 作为 Bearer 凭证，立刻发起 HTTP/3 建连！
	logToUI("INFO", "Bypassing Guardian block. Directly establishing HTTP/3 tunnel to %s...", bestNode)

	session, err := vpnclient.NewH3Session(bestNode, token, 15*time.Second, protectFunc)
	if err != nil {
		logToUI("ERROR", "HTTP/3 Upstream connect failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	activeSession = session
	logToUI("INFO", "HTTP/3 MASQUE tunnel established successfully!")

	// 4. 启动本地代理
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
