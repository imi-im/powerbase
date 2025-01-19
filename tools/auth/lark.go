package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

var _ Provider = (*LarkProvider)(nil)

// NameKakao is the unique name of the Kakao provider.
const NameLark string = "lark"

const (
	Name        = "lark"
	DisplayName = "Lark"
	// AuthURL     = "/oidc/oauth/lark/authorize"
	// TokenURL    = "/oidc/oauth/lark/token"
	// UserInfoURL = "/oidc/oauth/lark/userinfo"

	ORIG_AuthURL     = "https://open.feishu.cn/open-apis/authen/v1/authorize"
	ORIG_TokenURL    = "https://open.feishu.cn/open-apis/authen/v1/access_token"
	ORIG_UserInfoURL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

type larkUser struct {
	Sub              string `json:"open_id"`
	Name             string `json:"name"`
	Picture          string `json:"avatar_url"`
	Email            string `json:"email"`
	Phone            string `json:"mobile"`
	Username         string `json:"user_id"`
	Enterprise_email string `json:"enterprise_email"`
}
type LarkProvider struct {
	BaseProvider

	appToken    string
	appTokenExp time.Time
}

func init() {
	Providers[NameLark] = wrapFactory(NewLarkProvider)
}

func NewLarkProvider() Provider {
	p := &LarkProvider{}
	p.SetPKCE(false)
	p.SetDisplayName(DisplayName)
	p.SetAuthURL(ORIG_AuthURL)
	p.SetTokenURL(ORIG_TokenURL)
	p.SetUserInfoURL(ORIG_UserInfoURL)

	return p
}

//	func (p *LarkProvider) FetchRawUserInfo(token *oauth2.Token) ([]byte, error) {
//		var rurl = p.UserInfoURL()
//		req, err := http.NewRequest("GET", rurl, nil)
//		if err != nil {
//			return nil, err
//		}
//		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
//		return httpRequest(req)
//	}
func (p *LarkProvider) FetchAuthUser(token *oauth2.Token) (*AuthUser, error) {
	body, err := p.FetchRawUserInfo(token)
	if err != nil {
		return nil, err
	}
	ret := struct {
		Code int64    `json:"code"`
		Data larkUser `json:"data"`
	}{}
	err = json.Unmarshal(body, &ret)
	if err != nil || ret.Code != 0 {
		return nil, errors.New(string(body))
	}
	slog.Debug("lark user rawinfo", "user", string(body))
	b, _ := json.Marshal(ret.Data)
	rawUser := map[string]any{}
	json.Unmarshal(b, &rawUser)
	user := &AuthUser{
		Name:      ret.Data.Name,
		Id:        ret.Data.Sub,
		Email:     ret.Data.Email,
		AvatarURL: ret.Data.Picture,
		Username:  ret.Data.Username,
		RawUser:   rawUser,
	}
	if user.Email == "" {
		user.Email = ret.Data.Enterprise_email
	}

	if user.Username == "" {
		if user.Email != "" {
			username := strings.Split(user.Email, "@")[0]
			user.Username = username
		} else if ret.Data.Phone != "" {
			user.Username = ret.Data.Phone
		} else {
			slog.Warn("lark user no username, will be set to a random")
		}
	}
	return user, err
}
func (p *LarkProvider) FetchToken(code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	appToken, err := p.getAppToken()
	if err != nil {
		return nil, err
	}

	var url = p.TokenURL()
	info := `{"code":"` + code + `","grant_type":"authorization_code"}`

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(info)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+appToken)

	body, err := httpRequest(req)
	if err != nil {
		return nil, err
	}
	ret := struct {
		Code int64 `json:"code"`
		Data struct {
			Access_token       string `json:"access_token"`
			Refresh_token      string `json:"refresh_token"`
			Expires_in         int64  `json:"expires_in"`
			Refresh_expires_in int64  `json:"refresh_expires_in"`
		} `json:"data"`
	}{}
	err = json.Unmarshal(body, &ret)
	if err != nil || ret.Code != 0 {
		return nil, errors.New(string(body))
	}
	token := &oauth2.Token{
		AccessToken:  ret.Data.Access_token,
		RefreshToken: ret.Data.Refresh_token,
		Expiry:       time.Now().Add(time.Duration(ret.Data.Expires_in) * time.Second),
	}
	return token, nil
}

func httpRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (p *LarkProvider) getAppToken() (string, error) {
	if p.appToken != "" && time.Since(p.appTokenExp) < -10*time.Second {
		return p.appToken, nil
	}

	url := "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/"
	info := `{"app_id":"` + p.ClientId() + `","app_secret":"` + p.ClientSecret() + `"}`

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(info)))
	if err != nil {
		return "", err
	}

	body, err := httpRequest(req)
	if err != nil {
		return "", err
	}

	tokenInfo := struct {
		Code                int64  `json:"code"`
		Expire              int64  `json:"expire"`
		App_access_token    string `json:"app_access_token"`
		Tenant_access_token string `json:"tenant_access_token"`
	}{}
	err = json.Unmarshal(body, &tokenInfo)

	if err != nil || tokenInfo.Code != 0 {
		return "", errors.New(string(body))
	}
	// slog.Debug("getAppToken", "token", tokenInfo.App_access_token)
	p.appToken = tokenInfo.App_access_token
	p.appTokenExp = time.Now().Add(time.Duration(tokenInfo.Expire) * time.Second)
	return p.appToken, nil
}
