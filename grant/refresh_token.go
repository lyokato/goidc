package grant

import (
	"net/http"
	"time"

	"github.com/lyokato/goidc/log"
	"github.com/lyokato/goidc/scope"
	sd "github.com/lyokato/goidc/service_data"

	oer "github.com/lyokato/goidc/oauth_error"
)

const TypeRefreshToken = "refresh_token"

func RefreshToken() *GrantHandler {
	return &GrantHandler{
		TypeRefreshToken,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface, logger log.Logger) (*Response, *oer.OAuthError) {

			rt := r.FormValue("refresh_token")
			if rt == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'refresh_token' parameter")
			}

			old, err := sdi.FindAccessTokenByRefreshToken(rt)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Warn(log.TokenEndpointLog(TypeRefreshToken, log.InterfaceUnsupported,
						map[string]string{"method": "FindAccessTokenByRefreshToken"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if old == nil {
					logger.Warn(log.TokenEndpointLog(TypeRefreshToken, log.InterfaceError,
						map[string]string{"method": "FindAccessTokenByRefreshToken"},
						"the method returns (nil, nil)."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			if old.RefreshTokenExpiresIn()+old.CreatedAt() < time.Now().Unix() {
				logger.Info(log.TokenEndpointLog(TypeRefreshToken, log.RefreshTokenConditionMismatch,
					map[string]string{"client_id": c.Id()},
					"expired refresh_token"))
				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					"expired 'refresh_token'")
			}

			info, err := sdi.FindAuthInfoById(old.AuthId())
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Warn(log.TokenEndpointLog(TypeRefreshToken, log.InterfaceUnsupported,
						map[string]string{"method": "FindAuthInfoById"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {
					logger.Warn(log.TokenEndpointLog(TypeRefreshToken, log.InterfaceError,
						map[string]string{"method": "FindAuthInfoById"},
						"the method returns (nil, nil)."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}
			if info.ClientId() != c.Id() {
				logger.Info(log.TokenEndpointLog(TypeRefreshToken, log.AuthInfoConditionMismatch,
					map[string]string{"client_id": c.Id()}, "'client_id' mismatch"))
				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
			}
			scp := info.Scope()
			if !scope.IncludeOfflineAccess(scp) {
				logger.Info(log.TokenEndpointLog(TypeRefreshToken, log.ScopeConditionMismatch,
					map[string]string{"client_id": c.Id()}, "'offline_access' not found"))
				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
			}

			token, err := sdi.RefreshAccessToken(info, old, true)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Warn(log.TokenEndpointLog(TypeRefreshToken, log.InterfaceUnsupported,
						map[string]string{"method": "RefreshAccessToken"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {
					logger.Warn(log.TokenEndpointLog(TypeRefreshToken, log.InterfaceError,
						map[string]string{"method": "RefreshAccessToken"},
						"the method returns (nil, nil)."))
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
