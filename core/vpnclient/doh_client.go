package vpnclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// Mozilla 官方域名在 Cloudflare / AWS 上的真实 Anycast Clean IP 兜底池
var cleanIPMap = map[string][]string{
	"vpn.mozilla.org": {
		"104.16.132.229",
		"104.16.133.229",
		"172.67.138.12",
	},
	"firefox.settings.services.mozilla.com": {
		"34.117.237.239",
		"34.120.208.123",
	},
	"api.accounts.firefox.com": {
		"34.160.144.191",
		"34.111.164.14",
	},
}

var (
	dnsCache   = make(map[string]string)
	dnsCacheMu sync.RWMutex
)

// ResolveCleanIP 优先通过 AliDNS DoH 解析真实 IP，失败则使用内置官方 Anycast IP 兜底
func ResolveCleanIP(host string) string {
	dnsCacheMu.RLock()
	if ip, ok := dnsCache[host]; ok {
		dnsCacheMu.RUnlock()
		return ip
	}
	dnsCacheMu.RUnlock()

	// 1. 尝试通过阿里公共 DoH 获取未污染 IP (国内直连最快且不受 GFW 干扰)
	ip, err := queryAliDoH(host)
	if err == nil && ip != "" {
		dnsCacheMu.Lock()
		dnsCache[host] = ip
		dnsCacheMu.Unlock()
		return ip
	}

	// 2. DoH 失败，直接使用内置官方真实 Clean IP 池
	if ips, ok := cleanIPMap[host]; ok && len(ips) > 0 {
		return ips[0]
	}

	return host
}

func queryAliDoH(host string) (string, error) {
	url := fmt.Sprintf("https://223.5.5.5/resolve?name=%s&type=A", host)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var res struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(data, &res); err != nil || len(res.Answer) == 0 {
		return "", fmt.Errorf("doh parse failed")
	}

	for _, a := range res.Answer {
		if a.Type == 1 && net.ParseIP(a.Data) != nil {
			return a.Data, nil
		}
	}
	return "", fmt.Errorf("no ipv4 address found")
}

// NewAntiCensorshipHTTPClient 打造防污染专用 HTTP 客户端
// 强制将域名解析转向 Clean IP，但 TLS 证书验证依然保留原域名，保证握手合法
func NewAntiCensorshipHTTPClient(timeout time.Duration, protectFn func(fd int)) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if protectFn != nil {
				return c.Control(func(fd uintptr) {
					protectFn(int(fd))
				})
			}
			return nil
		},
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return dialer.DialContext(ctx, network, addr)
			}

			// 替换为真实未污染 IP 拨号
			cleanIP := ResolveCleanIP(host)
			target := net.JoinHostPort(cleanIP, port)
			return dialer.DialContext(ctx, network, target)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        10,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
