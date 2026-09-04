package vpnclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// Firefox for Android 官方客户端 ID
	FxAClientID     = "a2270f727f45f648"
	FxARedirectURI  = "https://accounts.firefox.com/oauth/success/a2270f727f45f648"
	// 使用带版本的完整授权端点
	FxAAuthorizeURL = "https://oauth.accounts.firefox.com/v1/authorization"
	FxATokenURL     = "https://oauth.accounts.firefox.com/v1/token"
)

type PKCESession struct {
	Verifier string
	AuthURL  string
}

// GeneratePKCEAuthURL 构建供 Android 打开的授权页面
func GeneratePKCEAuthURL() (*PKCESession, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	verifier := string(buf)

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// 核心修复：手动组装 Query，确保 scope 中的空格使用 %20 而不是引发歧义的 + 或 %2B
	scopes := "profile https://identity.mozilla.com/apps/vpn"
	
	params := []string{
		"client_id=" + url.QueryEscape(FxAClientID),
		"redirect_uri=" + url.QueryEscape(FxARedirectURI),
		"response_type=code",
		"access_type=offline",
		// 使用标准的 RFC 3986 百分比编码 %20 代替 +
		"scope=" + strings.ReplaceAll(url.QueryEscape(scopes), "+", "%20"),
		"code_challenge=" + url.QueryEscape(challenge),
		"code_challenge_method=S256",
		"action=email", // 显式提示首屏是输入邮箱
	}

	finalURL := FxAAuthorizeURL + "?" + strings.Join(params, "&")

	return &PKCESession{
		Verifier: verifier,
		AuthURL:  finalURL,
	}, nil
}

// ExchangeCode 用授权码换取长期凭证
func ExchangeCode(code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("client_id", FxAClientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("code_verifier", strings.TrimSpace(verifier))
	form.Set("redirect_uri", FxARedirectURI)

	req, err := http.NewRequest(http.MethodPost, FxATokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Android; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &res); err != nil || res.AccessToken == "" {
		return "", fmt.Errorf("parse token response failed: %s", string(data))
	}
	return res.AccessToken, nil
}
