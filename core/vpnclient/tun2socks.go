package vpnclient

import (
	"io"
	"net"
	"sync"
)

type LocalBridge struct {
	listener net.Listener
	closed   bool
	mu       sync.Mutex
}

func (b *LocalBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.listener != nil {
		return b.listener.Close()
	}
	return nil
}

// StartLocalSocksBridge 开启内部回环 SOCKS5 桥接
func StartLocalSocksBridge(session *H3Session) (*LocalBridge, string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}

	bridge := &LocalBridge{listener: l}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				bridge.mu.Lock()
				closed := bridge.closed
				bridge.mu.Unlock()
				if closed {
					return
				}
				continue
			}
			go handleClient(conn, session)
		}
	}()

	return bridge, l.Addr().String(), nil
}

func handleClient(client net.Conn, session *H3Session) {
	defer client.Close()

	// 1. SOCKS5 协商认证
	buf := make([]byte, 256)
	if _, err := io.ReadFull(client, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(client, buf[:nmethods]); err != nil {
		return
	}
	// 无需认证返回 0x05, 0x00
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. 获取目标地址
	if _, err := io.ReadFull(client, buf[:4]); err != nil || buf[1] != 0x01 {
		return // 只支持 CONNECT (0x01)
	}

	var targetHost string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(client, buf[:4]); err != nil {
			return
		}
		targetHost = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(client, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(client, buf[:domainLen]); err != nil {
			return
		}
		targetHost = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(client, buf[:16]); err != nil {
			return
		}
		targetHost = net.IP(buf[:16]).String()
	default:
		return
	}

	// 读取端口
	if _, err := io.ReadFull(client, buf[:2]); err != nil {
		return
	}
	port := (int(buf[0]) << 8) | int(buf[1])
	targetAddr := net.JoinHostPort(targetHost, string(rune(port)))

	// 3. 通过我们打磨好的 HTTP/3 MASQUE 打开远程隧道
	tunnel, err := session.OpenTunnel(targetAddr)
	if err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer tunnel.Close()

	// 响应成功
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 4. 双向中继（使用我们手写的 RingBuffer）
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		b := make([]byte, 32*1024)
		io.CopyBuffer(dst, src, b)
	}
	go pipe(tunnel, client)
	go pipe(client, tunnel)
	wg.Wait()
}
