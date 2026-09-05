package vpnclient

import (
	"context"
	"net"
	"syscall"
	"time"
)

type ServerCandidate struct {
	HostPort string
	Country  string
	Latency  time.Duration
}

// PingSingleNode 测试单个节点的连通性与往返延迟（毫秒），连不上返回 -1
func PingSingleNode(nodeAddr string, timeout time.Duration, protectFn func(fd int)) int64 {
	d := net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			if protectFn != nil {
				return c.Control(func(fd uintptr) {
					protectFn(int(fd))
				})
			}
			return nil
		},
	}

	start := time.Now()
	conn, err := d.DialContext(context.Background(), "tcp", nodeAddr)
	if err != nil {
		return -1 // 连不上或解析超时
	}
	defer conn.Close()

	return time.Since(start).Milliseconds()
}

// ProbeFastestNode 针对候选节点列表进行并发 RTT 测速（带 Socket 保护）
func ProbeFastestNode(endpoints []string, timeout time.Duration, protectFn func(fd int)) string {
	if len(endpoints) == 0 {
		return ""
	}
	type result struct {
		endpoint string
		rtt      time.Duration
	}

	resCh := make(chan result, len(endpoints))
	var timeoutCount int

	for _, ep := range endpoints {
		go func(addr string) {
			d := net.Dialer{
				Timeout: timeout,
				Control: func(network, address string, c syscall.RawConn) error {
					if protectFn != nil {
						return c.Control(func(fd uintptr) {
							protectFn(int(fd))
						})
					}
					return nil
				},
			}
			start := time.Now()
			conn, err := d.DialContext(context.Background(), "tcp", addr)
			if err == nil {
				conn.Close()
				resCh <- result{endpoint: addr, rtt: time.Since(start)}
			} else {
				resCh <- result{endpoint: addr, rtt: time.Hour}
			}
		}(ep)
	}

	var best string
	var minRTT time.Duration = time.Hour
	for i := 0; i < len(endpoints); i++ {
		r := <-resCh
		if r.rtt < minRTT {
			minRTT = r.rtt
			best = r.endpoint
		}
		if r.rtt == time.Hour {
			timeoutCount++
		}
	}

	return best
}
