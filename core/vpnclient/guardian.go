package vpnclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const GuardianEndpointDefault = "https://vpn.mozilla.org/api/v1/fpn/token"

// GetProxyPassWithToken 结合 DoH 与真实 Clean IP 获取 Proxy Pass
func GetProxyPassWithToken(accessToken string, protectFn func(fd int)) (string, error) {
	req, err := http.NewRequest(http.MethodGet, GuardianEndpointDefault, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:android)")

	// 使用防 DNS 污染与防握手阻断的专用 Client
	client := NewAntiCensorshipHTTPClient(10*time.Second, protectFn)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("guardian request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("guardian returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var res struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.Token == "" {
		return "", fmt.Errorf("empty proxy-pass token in guardian response: %s", string(body))
	}

	return res.Token, nil
}
