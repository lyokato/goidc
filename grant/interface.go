package grant

import (
	"encoding/json"
	"fmt"
	"net/http"

	oer "github.com/lyokato/goidc/oauth_error"
	sd "github.com/lyokato/goidc/service_data"
)

type (
	GrantHandlerFunc func(r *http.Request, c sd.ClientInterface, sdi sd.ServiceDataInterface) (*Response, *oer.OAuthError)

	GrantHandler struct {
		Type string
		Func GrantHandlerFunc
	}

	Response struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope",omitempty`
		IdToken      string `json:"id_token,omitempty"`
	}
)

func NewResponse(token string, expiresIn int64) *Response {
	return &Response{
		TokenType:   "Bearer",
		AccessToken: token,
		ExpiresIn:   expiresIn,
	}
}

func (r *Response) JSON() []byte {
	body, err := json.Marshal(r)
	if err != nil {
		// must not come here
		panic(fmt.Sprintf("broken JSON: %s", err))
	}
	return body
}
