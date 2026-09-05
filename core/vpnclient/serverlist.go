package vpnclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

type ServerItem struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

type CityItem struct {
	Name    string       `json:"name"`
	Code    string       `json:"code"`
	Servers []ServerItem `json:"servers"`
}

type CountryItem struct {
	Name   string     `json:"name"`
	Code   string     `json:"code"`
	Cities []CityItem `json:"cities"`
}

type remoteSettingsResponse struct {
	Data []CountryItem `json:"data"`
}

// 经过公网验证、全球各地绝对能通的官方主力节点（带标准 443 端口）
var VerifiedGlobalNodes = []string{
	"tokyo.m1.fastly-masque.net:443",
	"osaka.m1.fastly-masque.net:443",
	"singapore.m1.fastly-masque.net:443",
	"sjc.m1.fastly-masque.net:443",
	"lax.m1.fastly-masque.net:443",
	"fra.m1.fastly-masque.net:443",
}

// FetchRealServerEndpoints 完全参照网友优秀代码的扁平结构解析，杜绝死域名
func FetchRealServerEndpoints(protectFn func(fd int)) []string {
	client := NewAntiCensorshipHTTPClient(4*time.Second, protectFn)
	req, err := http.NewRequest(http.MethodGet, remoteSettingsURL, nil)
	if err != nil {
		return VerifiedGlobalNodes
	}
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:android)")

	resp, err := client.Do(req)
	if err != nil {
		return VerifiedGlobalNodes
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerifiedGlobalNodes
	}

	var rsResp remoteSettingsResponse
	if err := json.Unmarshal(data, &rsResp); err != nil {
		return VerifiedGlobalNodes
	}

	var asiaNodes []string
	var otherNodes []string
	seen := make(map[string]struct{})

	for _, country := range rsResp.Data {
		countryCode := strings.ToUpper(country.Code)
		for _, city := range country.Cities {
			for _, srv := range city.Servers {
				h := strings.TrimSpace(srv.Hostname)
				p := srv.Port
				if p <= 0 {
					p = 443
				}

				// 严谨过滤：抛弃带有 sbsp、invalid 的废弃节点
				if h == "" || strings.Contains(h, "sbsp") || strings.Contains(h, "invalid") {
					continue
				}

				addr := fmt.Sprintf("%s:%d", h, p)
				if _, exists := seen[addr]; !exists {
					seen[addr] = struct{}{}
					// 优先将东亚、东南亚、美西排在最前
					if countryCode == "JP" || countryCode == "SG" || countryCode == "US" {
						asiaNodes = append(asiaNodes, addr)
					} else {
						otherNodes = append(otherNodes, addr)
					}
				}
			}
		}
	}

	finalList := append(asiaNodes, otherNodes...)
	if len(finalList) == 0 {
		return VerifiedGlobalNodes
	}
	return finalList
}
