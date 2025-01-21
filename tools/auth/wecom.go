package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	WecomDisplayName = "企业微信"
	NameWecom        = "wecom"

	// AuthURL     = "/oidc/oauth/wecom/authorize"
	// TokenURL    = "/oidc/oauth/wecom/token"
	// UserInfoURL = "/oidc/oauth/wecom/userinfo"

	Wecom_ORIG_AuthURL     = "https://login.work.weixin.qq.com/wwlogin/sso/login"
	Wecom_ORIG_TokenURL    = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
	Wecom_ORIG_UserInfoURL = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail"
)

func init() {
	Providers[NameWecom] = wrapFactory(NewWecomProvider)
}

type WecomProvider struct {
	BaseProvider
	AgentID     string
	appToken    string
	appTokenExp time.Time
}

func NewWecomProvider() *WecomProvider {
	p := &WecomProvider{}
	p.SetPKCE(false)
	p.SetDisplayName(WecomDisplayName)
	// p.SetScopes([]string{"snsapi_privateinfo"})
	p.SetAuthURL(Wecom_ORIG_AuthURL)
	p.SetTokenURL(Wecom_ORIG_TokenURL)
	p.SetUserInfoURL(Wecom_ORIG_UserInfoURL)
	return p
}
func (p *WecomProvider) FetchToken(code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: code,
	}, nil
}
func (p *WecomProvider) FetchRawUserInfo(token *oauth2.Token) ([]byte, error) {
	appToken, err := p.getAppToken()
	if err != nil {
		return nil, err
	}
	var rurl = p.TokenURL() + "?access_token=" + appToken + "&code=" + token.AccessToken

	req, _ := http.NewRequest("GET", rurl, nil)
	return p.httpRequest(req)
}

func (p *WecomProvider) FetchAuthUser(token *oauth2.Token) (user *AuthUser, err error) {
	body, err := p.FetchRawUserInfo(token)

	if err != nil {
		// fmt.Println("FetchAuthUser", "body", string(body), "error", err)
		return nil, err
	}
	info := struct {
		Code        int64  `json:"errcode"`
		Error       string `json:"errmsg"`
		Userid      string `json:"userid"`
		User_ticket string `json:"user_ticket"`

		Openid          string `json:"openid"`
		External_userid string `json:"external_userid"`
	}{}
	json.Unmarshal(body, &info)

	if info.Code != 0 || info.Error != "ok" {
		return nil, errors.New(info.Error)
	}

	if info.User_ticket != "" {
		//可以获取详细资料
		user, err = p.getUserInfo(info.User_ticket)
		if err != nil {
			return nil, err
		}
	} else {
		if info.Openid != "" {
			return nil, errors.New("no access to openid")
		}
		//只能获取基本资料
		user = &AuthUser{
			Username: info.Userid,
		}
	}

	durl := "https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=" + p.appToken + "&userid=" + info.Userid
	req, _ := http.NewRequest("GET", durl, nil)

	body, err = p.httpRequest(req)
	if err != nil {
		return nil, err
	}
	var ret map[string]any
	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, err
	}
	if ret["errmsg"] != "ok" {
		return nil, errors.New(ret["errmsg"].(string))
	}
	if ret["status"].(float64) != 1 {
		return nil, fmt.Errorf("user status=%v, no access", ret["status"])
	}

	if ret["name"] != "" {
		user.Name = ret["name"].(string)
	}

	if info.Openid != "" {
		user.Id = info.Openid
	} else {
		//TODO 换取 openid
	}
	if user.Id == "" {
		user.Id = user.Username
	}
	return user, err
}

func (p *WecomProvider) httpRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (p *WecomProvider) BuildAuthURL(state string, opts ...oauth2.AuthCodeOption) string {
	url := "?response_type=code" +
		"&appid=" + p.ClientId() +
		"&state=" + state +
		"&login_type=CorpApp"
	// "#wechat_redirect"
	if agentId, ok := p.Extra()["agentId"]; ok {
		url = p.AuthURL() + url + "&scope=snsapi_privateinfo&agentid=" + agentId.(string)
	} else {
		ORIG_AuthURL := "https://open.weixin.qq.com/connect/oauth2/authorize"
		url = ORIG_AuthURL + url + "&scope=snsapi_base#wechat_redirect"
	}
	return url
}
func (p *WecomProvider) getAppToken() (string, error) {
	//Share token in app store
	if p.appToken != "" && time.Since(p.appTokenExp) < -10*time.Second {
		return p.appToken, nil
	}

	url := "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=" +
		p.ClientId() +
		"&corpsecret=" +
		p.ClientSecret()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	body, err := p.httpRequest(req)
	if err != nil {
		return "", err
	}

	tokenInfo := struct {
		Code             int64  `json:"errcode"`
		Expire           int64  `json:"expires_in"`
		App_access_token string `json:"access_token"`
	}{}
	json.Unmarshal(body, &tokenInfo)

	if tokenInfo.Code != 0 {
		return "", errors.New(string(body))
	}

	p.appToken = tokenInfo.App_access_token
	p.appTokenExp = time.Now().Add(time.Duration(tokenInfo.Expire) * time.Second)
	return p.appToken, nil
}

func (p *WecomProvider) getUserInfo(ticket string) (*AuthUser, error) {
	appToken, err := p.getAppToken()
	if err != nil {
		return nil, err
	}

	var rurl = p.UserInfoURL() + "?access_token=" + appToken
	info := `{"user_ticket":"` + ticket + `"}`
	req, _ := http.NewRequest("POST", rurl, bytes.NewBuffer([]byte(info)))

	body, err := p.httpRequest(req)
	if err != nil {
		return nil, err
	}
	// slog.Debug("getUserDetail", "url", rurl, "ticket", info)

	/*
			{
		   "errcode": 0,
		   "errmsg": "ok",
		   "userid":"lisi",
		   "gender":"1",
		   "avatar":"http://shp.qpic.cn/bizmp/xxxxxxxxxxx/0",
		   "qr_code":"https://open.work.weixin.qq.com/wwopen/userQRCode?vcode=vcfc13b01dfs78e981c",
		   "mobile": "13800000000",
		   "email": "zhangsan@gzdev.com",
		   "biz_mail":"zhangsan@qyycs2.wecom.work",
		   "address": "广州市海珠区新港中路"
		}
	*/
	var ret map[string]any
	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, err
	}
	if ret["errmsg"] != "ok" {
		return nil, errors.New(ret["errmsg"].(string))
	}
	delete(ret, "errcode")
	delete(ret, "errmsg")
	user := &AuthUser{
		Username:  ret["userid"].(string),
		AvatarURL: ret["avatar"].(string),
	}
	if email := ret["email"].(string); email != "" {
		user.Email = email
	} else {
		if email := ret["biz_mail"].(string); email != "" {
			user.Email = email
		}
		delete(ret, "email")
	}
	user.RawUser = ret
	// slog.Debug("getUserInfo", "info", ret)
	return user, nil
}
