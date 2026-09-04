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

// LoginWithPassword 原生账号密码登录（带官方 Client ID 签名）
func LoginWithPassword(email, password string) (*DirectLoginResult, error) {
	logToUI("INFO", "Logging in with official Mozilla VPN client ID...")
	resp, err := vpnclient.DirectLogin(email, password)
	if err != nil {
		logToUI("ERROR", "Login failed: %v", err)
		return nil, err
	}

	// 账号触发二次验证
	if !resp.Verified {
		logToUI("WARN", "Account requires email 2FA verification")
		return &DirectLoginResult{
			SessionToken: resp.SessionToken,
			Need2FA:      true,
		}, nil
	}

	// 直接换取 OAuth AccessToken
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

// Submit2FACode 提交邮箱验证码
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

// StartEngine 自动通过 DoH/Clean-IP 换取 ProxyPass 并连接真实 Fastly MASQUE 节点
func StartEngine(accessToken string, bridge AndroidBridge) (string, error) {
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

	// 1. 通过防污染通道拉取官方节点（若超时秒切内置真实官方节点池）
	logToUI("INFO", "Loading official Fastly nodes (with DoH/Clean-IP protection)...")
	endpoints := vpnclient.FetchRealServerEndpoints(protectFunc)
	logToUI("INFO", "Loaded %d candidate nodes", len(endpoints))

	// 2. 并发探测最低延迟节点 (取前 5 个进行快速 RTT 竞速)
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

	// 3. 用 AccessToken 通过防 DNS 污染与 Clean IP 通道向 Guardian 换取 Proxy Pass JWT
	logToUI("INFO", "Fetching Proxy Pass JWT via Clean IP...")
	proxyPassJWT, err := vpnclient.GetProxyPassWithToken(accessToken, protectFunc)
	if err != nil {
		logToUI("ERROR", "Fetch Proxy Pass failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	logToUI("INFO", "Proxy Pass obtained! Connecting HTTP/3 tunnel to %s...", bestNode)

	// 4. 建立底层抗丢包 HTTP/3 (QUIC/UDP) 隧道
	session, err := vpnclient.NewH3Session(bestNode, proxyPassJWT, 15*time.Second, protectFunc)
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

// StopEngine 停止并关闭所有网络通道
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
