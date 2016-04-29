package grant

import (
	"net/http"
	"time"

	sd "github.com/lyokato/goidc/service_data"

	oer "github.com/lyokato/goidc/oauth_error"
)

func RefreshToken() *GrantHandler {
	return &GrantHandler{
		"refresh_token",
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface) (*Response, *oer.OAuthError) {

			rt := r.FormValue("refresh_token")
			if rt == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
			}

			old_rt, err := sdi.FindRefreshToken(rt)
			if err != nil {
				// Case not found, or internal server error
				return nil, err
			}

			if old_rt.ExpiresIn()+old_rt.CreatedAt() < time.Now().Unix() {
				// Expired RefreshToken
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
			}

			info, err := sdi.FindAuthInfoById(old_rt.AuthId())
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
			}
			if info.ClientId() != c.Id() {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
			}

			// OPTIONAL
			// scope := r.FormValue("scope")

			token, err := sdi.CreateAccessToken(info)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
			}

			new_rt, err := sdi.CreateRefreshToken(info)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
			}

			// TODO delete old RefreshToken?

			res := NewResponse(token.Token(), token.ExpiresIn())
			scp := info.Scope()
			if scp != "" {
				res.Scope = scp
			}
			if new_rt != nil {
				res.RefreshToken = new_rt.Token()
			}
			return res, nil
		},
	}
}
