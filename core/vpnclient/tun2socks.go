package vpnclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type TunEngine struct {
	file   *os.File
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (t *TunEngine) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.file != nil {
		t.file.Close()
	}
	t.wg.Wait()
	return nil
}

// StartTun2Socks 使用 Google gVisor 用户态协议栈桥接 TUN 网卡到本地 SOCKS 端口
func StartTun2Socks(tunFd int, mtu int, localSocksAddr string) (io.Closer, error) {
	// 设置非阻塞
	if err := unix.SetNonblock(tunFd, true); err != nil {
		syscall.SetNonblock(tunFd, true)
	}
	file := os.NewFile(uintptr(tunFd), "tun")

	// 1. 创建虚拟网络栈
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	// 2. 创建虚拟通信信道 Link Endpoint
	linkEP := channel.New(512, uint32(mtu), "")
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		file.Close()
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	// 拦截所有网段 (混杂模式 / 默认路由)
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet(), NIC: nicID})
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet(), NIC: nicID})

	ctx, cancel := context.WithCancel(context.Background())
	engine := &TunEngine{
		file:   file,
		cancel: cancel,
	}

	// 3. 读 TUN 设备并输入 gVisor 协议栈
	engine.wg.Add(1)
	go func() {
		defer engine.wg.Done()
		buf := make([]byte, mtu)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := file.Read(buf)
				if err != nil {
					return
				}
				if n > 0 {
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: buffer.MakeWithData(buf[:n]),
					})
					linkEP.InjectInbound(header.IPv4ProtocolNumber, pkt)
					pkt.DecRef()
				}
			}
		}
	}()

	// 4. 从协议栈取出发出的包，写回 TUN 设备
	engine.wg.Add(1)
	go func() {
		defer engine.wg.Done()
		for {
			pkt := linkEP.ReadContext(ctx)
			if pkt == nil {
				return
			}
			data := pkt.ToView().AsSlice()
			_, _ = file.Write(data)
			pkt.DecRef()
		}
	}()

	// 5. 监听 TCP 连接并转发到本地回环 SOCKS
	tcpHandler := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		req := r
		go func() {
			var wq waiterQueue
			ep, err := req.CreateEndpoint(&wq)
			if err != nil {
				req.Complete(true)
				return
			}
			req.Complete(false)

			tunConn := gonet.NewTCPConn(&wq, ep)
			defer tunConn.Close()

			// 连接到本地 SOCKS 回环端口
			socksConn, err := net.Dial("tcp", localSocksAddr)
			if err != nil {
				return
			}
			defer socksConn.Close()

			// 代理中继
			relayBidirectional(tunConn, socksConn)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	return engine, nil
}

type waiterQueue struct {
	tcpip.DefaultSocketOptions
}

func relayBidirectional(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyFunc := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		io.CopyBuffer(dst, src, buf)
	}
	go copyFunc(c1, c2)
	go copyFunc(c2, c1)
	wg.Wait()
}
