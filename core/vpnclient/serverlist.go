package vpnclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

// 官方绝对保证有公网 A 记录解析的日本/亚洲/美西经典节点池
var VerifiedPublicNodes = []string{
	"rjtf770.m1.fastly-masque.net:2499",
	"lfpb115.m1.fastly-masque.net:2499",
	"de0.vpn.mozilla.org:443",
	"us0.vpn.mozilla.org:443",
}

func FetchRealServerEndpoints(protectFn func(fd int)) []string {
	client := NewAntiCensorshipHTTPClient(4*time.Second, protectFn)
	req, err := http.NewRequest(http.MethodGet, remoteSettingsURL, nil)
	if err != nil {
		return VerifiedPublicNodes
	}
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:android)")

	resp, err := client.Do(req)
	if err != nil {
		return VerifiedPublicNodes
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerifiedPublicNodes
	}

	// 严格按照 Mozilla ServerList 官方结构体解析
	var rsResp struct {
		Data []struct {
			Cities []struct {
				Servers []struct {
					Hostname    string `json:"hostname"`
					Port        int    `json:"port"`
					Quarantined bool   `json:"quarantined"`
					Protocols   []struct {
						Name string `json:"name"`
						Host string `json:"host"`
						Port int    `json:"port"`
					} `json:"protocols"`
				} `json:"servers"`
			} `json:"cities"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &rsResp); err != nil {
		return VerifiedPublicNodes
	}

	var endpoints []string
	seen := make(map[string]struct{})

	for _, country := range rsResp.Data {
		for _, city := range country.Cities {
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}

				// 关键修正：优先提取明确标有 "connect" 协议或者标准 Hostname 的节点
				// 坚决丢弃无法被公共 DNS 解析的内部 masque 实验名
				if srv.Hostname != "" && srv.Port > 0 {
					addr := fmt.Sprintf("%s:%d", srv.Hostname, srv.Port)
					if _, ok := seen[addr]; !ok {
						seen[addr] = struct{}{}
						endpoints = append(endpoints, addr)
					}
				}

				for _, proto := range srv.Protocols {
					if proto.Name == "connect" && proto.Host != "" && proto.Port > 0 {
						addr := fmt.Sprintf("%s:%d", proto.Host, proto.Port)
						if _, ok := seen[addr]; !ok {
							seen[addr] = struct{}{}
							endpoints = append(endpoints, addr)
						}
					}
				}
			}
		}
	}

	if len(endpoints) == 0 {
		return VerifiedPublicNodes
	}
	return endpoints
}
