package grant

import (
	"net/http"
	"time"

	"github.com/lyokato/goidc/scope"
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
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'refresh_token' parameter")
			}

			old, err := sdi.FindAccessTokenByRefreshToken(rt)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if old == nil {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			if old.RefreshTokenExpiresIn()+old.CreatedAt() < time.Now().Unix() {
				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					"expired 'refresh_token'")
			}

			info, err := sdi.FindAuthInfoById(old.AuthId())
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}
			if info.ClientId() != c.Id() {
				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
			}
			scp := info.Scope()
			if !scope.IncludeOfflineAccess(scp) {
				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
			}

			token, err := sdi.RefreshAccessToken(info, old, true)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			res := NewResponse(token.AccessToken(), token.AccessTokenExpiresIn())
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
