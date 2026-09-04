package vpnclient

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

type TunEngine struct {
	key string
}

func (t *TunEngine) Close() error {
	engine.Stop()
	return nil
}

// StartTun2Socks 将 Android 传过来的 tunFd 与本地回环 SOCKS5 打通
func StartTun2Socks(tunFd int, mtu int, localSocksAddr string) (io.Closer, error) {
	host, portStr, err := net.SplitHostPort(localSocksAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid socks addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid socks port: %w", err)
	}

	// 1. 通过 Android 提供的文件描述符打开 TUN 设备
	dev, err := tun.OpenFromFd(tunFd)
	if err != nil {
		return nil, fmt.Errorf("open tun from fd %d failed: %w", tunFd, err)
	}

	// 2. 配置纯 Go 网络栈 (gVisor engine) 将 IP 包转换为 SOCKS5 流量
	engine.InsertDevice(dev)
	engine.SetMTU(mtu)

	// 配置上游出口为我们本地的 SOCKS 回环端口
	engine.AddSocks5Handler(host, uint16(port), "", "")

	// 启动协议栈引擎
	if err := engine.Start(); err != nil {
		return nil, fmt.Errorf("start tun2socks engine failed: %w", err)
	}

	return &TunEngine{}, nil
}
