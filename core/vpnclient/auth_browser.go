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
	FxAClientID     = "a2270f727f45f648" // 官方 Firefox for Android Client
	FxAScope        = "profile https://identity.mozilla.com/apps/vpn"
	FxARedirectURI  = "https://accounts.firefox.com/oauth/success/a2270f727f45f648"
	FxAAuthorizeURL = "https://oauth.accounts.firefox.com/v1/authorization"
	FxATokenURL     = "https://oauth.accounts.firefox.com/v1/token"
)

type PKCESession struct {
	Verifier string
	AuthURL  string
}

// GeneratePKCEAuthURL 构建供 Android WebView/CustomTabs 打开的官方授权页面
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

	u, _ := url.Parse(FxAAuthorizeURL)
	q := url.Values{}
	q.Set("client_id", FxAClientID)
	q.Set("scope", FxAScope)
	q.Set("response_type", "code")
	q.Set("access_type", "offline")
	q.Set("redirect_uri", FxARedirectURI)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return &PKCESession{
		Verifier: verifier,
		AuthURL:  u.String(),
	}, nil
}

// ExchangeCode 用授权码换取长期凭证
func ExchangeCode(code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("client_id", FxAClientID)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", FxARedirectURI)

	req, err := http.NewRequest(http.MethodPost, FxATokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &res); err != nil || res.AccessToken == "" {
		return "", fmt.Errorf("token exchange failed: %s", string(data))
	}
	return res.AccessToken, nil
}
