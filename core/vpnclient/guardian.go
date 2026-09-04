package vpnclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// 官方端点与 Cloudflare Pages/Worker 免费中继端点池
var guardianEndpoints = []string{
	"https://vpn.mozilla.org/api/v1/fpn/token",
	// 公共安全反代镜像（专门绕过 GFW 对 vpn.mozilla.org 的 SNI 丢包）：
	"https://mozilla-vpn-gateway.deno.dev/api/v1/fpn/token",
}

// GetProxyPassWithToken 自动尝试主备网关，只要一个通即可拿到 Pass
func GetProxyPassWithToken(accessToken string, protectFn func(fd int)) (string, error) {
	client := NewAntiCensorshipHTTPClient(6*time.Second, protectFn)

	var lastErr error
	for _, ep := range guardianEndpoints {
		req, err := http.NewRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:android; iap:true)")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue // 主端点超时，立即尝试备用中继通道
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}

		var res struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &res); err == nil && res.Token != "" {
			return res.Token, nil // 成功获取！
		}
	}

	return "", fmt.Errorf("all guardian endpoints failed: %v", lastErr)
}
