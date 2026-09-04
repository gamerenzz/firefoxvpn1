package vpnclient

import (
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

var (
	dnsCache   = make(map[string]string)
	dnsCacheMu sync.RWMutex
)

// ResolveCleanIP 优先通过 AliDNS DoH 解析真实未污染 IP，防止国内运营商报 no such host
func ResolveCleanIP(host string) string {
	dnsCacheMu.RLock()
	if ip, ok := dnsCache[host]; ok {
		dnsCacheMu.RUnlock()
		return ip
	}
	dnsCacheMu.RUnlock()

	// 1. 尝试通过阿里公共 DoH 获取真实解析 (国内直连最快且不受 GFW 干扰)
	ip, err := queryAliDoH(host)
	if err == nil && ip != "" {
		dnsCacheMu.Lock()
		dnsCache[host] = ip
		dnsCacheMu.Unlock()
		return ip
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

// NewAntiCensorshipHTTPClient 保证合法的 TLS 握手，同时避免套接字回环
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
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        10,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
