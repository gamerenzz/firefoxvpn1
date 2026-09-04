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

// StartEngine 自动用 AccessToken 换取 ProxyPass，并建立隧道，安全拦截所有异常
func StartEngine(accessToken string, selectedNode string, bridge AndroidBridge) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			logToUI("FATAL", "Recovered from panic: %v", r)
		}
	}()

	RegisterBridge(bridge)
	bridge.OnStatusUpdate("CONNECTING")

	// 1. 先用 AccessToken 向 Guardian 换取真正的 Proxy Pass (JWT)
	logToUI("INFO", "Fetching Proxy Pass from Mozilla Guardian...")
	proxyPassJWT, err := vpnclient.GetProxyPassWithToken(accessToken)
	if err != nil {
		logToUI("ERROR", "Fetch Proxy Pass failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	logToUI("INFO", "Proxy Pass obtained! Starting H3 MASQUE -> %s", selectedNode)

	// 2. 建立 HTTP/3 隧道
	session, err := vpnclient.NewH3Session(selectedNode, proxyPassJWT, 15*time.Second, func(fd int) {
		bridge.ProtectSocket(fd)
	})
	if err != nil {
		logToUI("ERROR", "H3 Connection Failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	activeSession = session

	// 3. 启动本地代理
	br, localAddr, err := vpnclient.StartLocalSocksBridge(session)
	if err != nil {
		logToUI("ERROR", "Local SOCKS Bridge Failed: %v", err)
		bridge.OnStatusUpdate("FAILED")
		return "", err
	}
	localBridge = br

	logToUI("INFO", "VPN Core Online! Listening at: %s", localAddr)
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
