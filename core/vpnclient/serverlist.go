package vpnclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

type Protocol struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

type City struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	Servers []Server `json:"servers"`
}

type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

type remoteSettingsResponse struct {
	Data []Country `json:"data"`
}

// FetchRealServerEndpoints 从 Mozilla 官方拉取真实可用的 Fastly MASQUE 节点与端口
func FetchRealServerEndpoints() ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, remoteSettingsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:android)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch serverlist failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rsResp remoteSettingsResponse
	if err := json.Unmarshal(data, &rsResp); err != nil {
		return nil, fmt.Errorf("parse serverlist json failed: %w", err)
	}

	var endpoints []string
	for _, country := range rsResp.Data {
		for _, city := range country.Cities {
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}
				// 优先获取支持 MASQUE / CONNECT 的节点
				if len(srv.Protocols) > 0 {
					for _, proto := range srv.Protocols {
						if proto.Host != "" && proto.Port > 0 {
							endpoints = append(endpoints, fmt.Sprintf("%s:%d", proto.Host, proto.Port))
						}
					}
				} else if srv.Hostname != "" && srv.Port > 0 {
					endpoints = append(endpoints, fmt.Sprintf("%s:%d", srv.Hostname, srv.Port))
				}
			}
		}
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no available servers found in Mozilla remote settings")
	}
	return endpoints, nil
}
