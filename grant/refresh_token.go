package grant

import (
	"net/http"
	"time"

	sd "github.com/lyokato/goidc/service_data"

	oer "github.com/lyokato/goidc/oauth_error"
)

const TypeRefreshToken = "refresh_token"

func RefreshToken() *GrantHandler {
	return &GrantHandler{
		TypeRefreshToken,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface) (*Response, *oer.OAuthError) {

			rt := r.FormValue("refresh_token")
			if rt == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			old, err := sdi.FindAccessTokenByRefreshToken(rt)
			if err != nil {
				// not found or expire
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			// check refresh-token's expiration
			if old.RefreshTokenExpiresIn()+old.CreatedAt() < time.Now().Unix() {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			info, err := sdi.FindAuthInfoById(old.AuthId())
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			if info.ClientId() != c.Id() {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			// OPTIONAL
			// scope := r.FormValue("scope")

			token, err := sdi.RefreshAccessToken(info, old, true)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			res := NewResponse(token.AccessToken(), token.AccessTokenExpiresIn())
			scp := info.Scope()
			if scp != "" {
				res.Scope = scp
			}

			newRt := token.RefreshToken()
			if newRt != "" {
				res.RefreshToken = newRt
			}
			return res, nil
		},
	}
}
