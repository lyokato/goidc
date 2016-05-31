package authorization

import (
	"encoding/base64"
	"encoding/json"

	"github.com/lyokato/goidc/flow"
	"github.com/lyokato/goidc/response_mode"
)

const (
	ErrMissingClientId = iota
	ErrMissingRedirectURI
	ErrInvalidRedirectURI
	ErrServerError
)

const (
	ResponseModeQuery    = "query"
	ResponseModeFragment = "fragment"
	ResponseModeFormPost = "form_post"
)

const (
	DisplayTypePopup = "popup"
	DisplayTypeTouch = "touch"
	DisplayTypeWAP   = "wap"
	DisplayTypePage  = "page"
)

const (
	DefaultMaxMaxAge             = 86400
	DefaultMinMaxAge             = 60
	DefaultMaxNonceLength        = 255
	DefaultMaxCodeVerifierLength = 255
	DefaultConsentOmissionPeriod = 86400
	DefaultAuthSessionExpiresIn  = 60
	DefaultIdTokenExpiresIn      = 86400
)

type (
	Policy struct {
		MaxMaxAge                                int
		MinMaxAge                                int
		AllowEmptyScope                          bool
		MaxNonceLength                           int
		MaxCodeVerifierLength                    int
		ConsentOmissionPeriod                    int
		AuthSessionExpiresIn                     int
		IdTokenExpiresIn                         int
		DefaultAuthorizationCodeFlowResponseMode string
		DefaultImplicitFlowResponseMode          string
		IgnoreInvalidResponseMode                bool
		RequireResponseModeSecurityLevelCheck    bool
	}

	Request struct {
		Flow         *flow.Flow `json:"flow"`
		ClientId     string     `json:"client_id"`
		Scope        string     `json:"scope"`
		RedirectURI  string     `json:"redirect_uri"`
		ResponseMode string     `json:"response_mode"`
		State        string     `json:"state"`
		CodeVerifier string     `json:"code_verifier"`
		Nonce        string     `json:"nonce"`
		Display      string     `json:"display"`
		Prompt       string     `json:"prompt"`
		MaxAge       int64      `json:"max_age"`
		UILocales    string     `json:"ui_locales"`
		IDTokenHint  string     `json:"id_token_hint"`
		LoginHint    string     `json:"login_hint"`
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

func DefaultPolicy() *Policy {
	return &Policy{
		MaxMaxAge:                                DefaultMaxMaxAge,
		MinMaxAge:                                DefaultMinMaxAge,
		AllowEmptyScope:                          false,
		MaxNonceLength:                           DefaultMaxNonceLength,
		MaxCodeVerifierLength:                    DefaultMaxCodeVerifierLength,
		ConsentOmissionPeriod:                    DefaultConsentOmissionPeriod,
		AuthSessionExpiresIn:                     DefaultAuthSessionExpiresIn,
		IdTokenExpiresIn:                         DefaultIdTokenExpiresIn,
		DefaultAuthorizationCodeFlowResponseMode: response_mode.Query,
		DefaultImplicitFlowResponseMode:          response_mode.Fragment,
		IgnoreInvalidResponseMode:                true,
		RequireResponseModeSecurityLevelCheck:    true,
	}
}

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
