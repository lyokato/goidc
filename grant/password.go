package grant

import (
	"net/http"

	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/scope"
	sd "github.com/lyokato/goidc/service_data"
)

const TypePassword = "password"

func Password() *GrantHandler {
	return &GrantHandler{
		TypePassword,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface) (*Response, *oer.OAuthError) {
			// REQUIRED
			username := r.FormValue("username")
			if username == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			// REQUIRED
			password := r.FormValue("password")
			if password == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			// OPTIONAL
			scp_req := r.FormValue("scope")

			uid, err := sdi.FindUserId(username, password)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			info, err := sdi.CreateOrUpdateAuthInfoDirect(uid, c.Id(), scp_req)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			token, err := sdi.CreateAccessToken(info,
				scope.IncludeOfflineAccess(info.Scope()))
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
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
