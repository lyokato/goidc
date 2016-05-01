package grant

import (
	"net/http"

	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/scope"
	sd "github.com/lyokato/goidc/service_data"
)

const TypeClientCredentials = "client_credentials"

func ClientCredentials() *GrantHandler {
	return &GrantHandler{
		TypeClientCredentials,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface) (*Response, *oer.OAuthError) {

			uid, err := sdi.FindClientUserId(c.Id(), c.Secret())
			if err != nil {
				// server error?
				return nil, err
			}

			scp_req := r.FormValue("scope")

			//CreateOrUpdateAuthInfo(uid int64, clientId, redirectURI, subject, scope string,
			//	authroizedAt int64, code string, codeExpiresIn int64, codeVerifier, nonce string) (AuthInfoInterface, *oer.OAuthError)
			info, err := sdi.CreateOrUpdateAuthInfoDirect(uid, c.Id(), scp_req)
			if err != nil {
				return nil, err
			}

			token, err := sdi.CreateAccessToken(info,
				scope.IncludeOfflineAccess(info.Scope()))
			if err != nil {
				return nil, err
			}

			res := NewResponse(token.AccessToken(), token.AccessTokenExpiresIn())

			scp := info.Scope()
			if scp != "" {
				res.Scope = scp
			}
			rt := token.RefreshToken()
			if rt != "" {
				res.RefreshToken = rt
			}
			return res, nil
		},
	}
}
