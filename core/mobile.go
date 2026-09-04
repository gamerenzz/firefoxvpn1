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

// LoginWithPassword 原生账号密码登录（彻底告别浏览器和 109 错误）
func LoginWithPassword(email, password string) (*DirectLoginResult, error) {
	logToUI("INFO", "Logging in with official Mozilla VPN client ID...")
	resp, err := vpnclient.DirectLogin(email, password)
	if err != nil {
		logToUI("ERROR", "Login failed: %v", err)
		return nil, err
	}

	// 如果需要输入邮箱验证码
	if !resp.Verified {
		logToUI("WARN", "Account requires email 2FA verification")
		return &DirectLoginResult{
			SessionToken: resp.SessionToken,
			Need2FA:      true,
		}, nil
	}

	// 如果已验证，直接换取 OAuth AccessToken
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

// StartEngine 启动底层 HTTP/3 隧道
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
