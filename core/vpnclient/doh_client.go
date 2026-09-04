package vpnclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"syscall"
	"time"
)

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
