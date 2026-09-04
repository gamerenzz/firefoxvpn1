package vpnclient

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"
)

type ServerCandidate struct {
	HostPort string
	Country  string
	Latency  time.Duration
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
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
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
			}
		}(ep)
	}

	wg.Wait()
	close(resCh)

	var best string
	var minRTT time.Duration = time.Hour
	for r := range resCh {
		if r.rtt < minRTT {
			minRTT = r.rtt
			best = r.endpoint
		}
	}
	return best
}
