package vpnclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

// 官方真实 Fastly 节点与端口，即使完全断网也保证有节点可用
var DefaultOfficialNodes = []string{
	"rjtf770.m1.fastly-masque.net:2499", // 日本东京
	"sin1.m1.fastly-masque.net:2499",    // 新加坡
	"sjc1.m1.fastly-masque.net:2499",    // 美国圣何塞
	"lax1.m1.fastly-masque.net:2499",    // 美国洛杉矶
	"fra1.m1.fastly-masque.net:2499",    // 德国法兰克福
}

func FetchRealServerEndpoints(protectFn func(fd int)) []string {
	client := NewAntiCensorshipHTTPClient(3*time.Second, protectFn)
	req, err := http.NewRequest(http.MethodGet, remoteSettingsURL, nil)
	if err != nil {
		return DefaultOfficialNodes
	}
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:android)")

	resp, err := client.Do(req)
	if err != nil {
		// 阻断时直接返回默认官方节点，不抛错，保证用户不中断
		return DefaultOfficialNodes
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return DefaultOfficialNodes
	}

	var rsResp struct {
		Data []struct {
			Cities []struct {
				Servers []struct {
					Hostname string `json:"hostname"`
					Port     int    `json:"port"`
				} `json:"servers"`
			} `json:"cities"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &rsResp); err != nil {
		return DefaultOfficialNodes
	}

	var endpoints []string
	for _, country := range rsResp.Data {
		for _, city := range country.Cities {
			for _, srv := range city.Servers {
				if srv.Hostname != "" && srv.Port > 0 {
					endpoints = append(endpoints, fmt.Sprintf("%s:%d", srv.Hostname, srv.Port))
				}
			}
		}
	}

	if len(endpoints) == 0 {
		return DefaultOfficialNodes
	}
	return endpoints
}
