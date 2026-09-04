package vpnclient

import (
	"io"
	"log"
	"net"
	"os"

	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/socks"
)

// StartTun2Socks 将 Android 传过来的 tunFd 与底层隧道打通
func StartTun2Socks(tunFd int, mtu int, localSocksAddr string) io.Closer {
	file := os.NewFile(uintptr(tunFd), "tun")
	lwipStack := core.NewLWIPStack()

	core.RegisterTCPConnHandler(socks.NewTCPHandler(localSocksAddr))
	core.RegisterOutputFunc(func(data []byte) (int, error) {
		return file.Write(data)
	})

	go func() {
		buf := make([]byte, mtu)
		for {
			n, err := file.Read(buf)
			if err != nil {
				return
			}
			lwipStack.Write(buf[:n])
		}
	}()

	log.Println("tun2socks engine started")
	return file
}
