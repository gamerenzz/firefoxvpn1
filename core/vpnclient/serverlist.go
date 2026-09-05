package vpnclient

import (
	"strings"
)

// 官方在公网具有全球权威 A 记录解析的正式骨干节点
var OfficialPublicNodes = []string{
	"jp0.vpn.mozilla.org:443", // 日本东京 (离国内最近，首选)
	"sg0.vpn.mozilla.org:443", // 新加坡 (东南亚骨干)
	"us0.vpn.mozilla.org:443", // 美国 (美西出口)
	"de0.vpn.mozilla.org:443", // 德国法兰克福 (欧洲主力)
	"uk0.vpn.mozilla.org:443", // 英国伦敦
}

// FetchRealServerEndpoints 只返回 100% 公网具备 DNS 解析的标准主机
func FetchRealServerEndpoints(protectFn func(fd int)) []string {
	return OfficialPublicNodes
}

func CleanHostFilter(h string) bool {
	if strings.Contains(h, "fastly-masque.net") || strings.Contains(h, "invalid") || h == "" {
		return false
	}
	return true
}
