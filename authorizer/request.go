package authorizer

import (
	"encoding/base64"
	"encoding/json"
)

const (
	DisplayTypePopup = "popup"
	DisplayTypeTouch = "touch"
	DisplayTypeWAP   = "wap"
	DisplayTypePage  = "page"
)

type (
	Request struct {
		Flow         *Flow  `json:"flow"`
		ClientId     string `json:"client_id"`
		Scope        string `json:"scope"`
		RedirectURI  string `json:"redirect_uri"`
		State        string `json:"state"`
		CodeVerifier string `json:"code_verifier"`
		Nonce        string `json:"nonce"`
		Display      string `json:"display"`
		Prompt       string `json:"prompt"`
		MaxAge       int64  `json:"max_age"`
		UILocales    string `json:"ui_locales"`
		IDTokenHint  string `json:"id_token_hint"`
		LoginHint    string `json:"login_hint"`
	}

	Session struct {
		RedirectURI  string
		Code         string
		ExpiresIn    int64
		CodeVerifier string
		Nonce        string
		AuthTime     int64
	}
)

func (r *Request) Encode() string {
	data, _ := json.Marshal(r)
	return base64.URLEncoding.EncodeToString(data)
}

func DecodeRequest(encoded string) *Request {
	data, _ := base64.URLEncoding.DecodeString(encoded)
	var r Request
	json.Unmarshal(data, &r)
	return &r
}

func (r *Request) ToSession(code string, expiresIn, authTime int64) *Session {
	return &Session{
		Code:         code,
		ExpiresIn:    expiresIn,
		RedirectURI:  r.RedirectURI,
		CodeVerifier: r.CodeVerifier,
		Nonce:        r.Nonce,
		AuthTime:     authTime,
	}
}
