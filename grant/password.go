package grant

import (
	"net/http"

	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/scope"
	sd "github.com/lyokato/goidc/service_data"
)

const TypePassword = "password"

func Password() *GrantHandler {
	return &GrantHandler{
		TypePassword,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface, logger log.Logger) (*Response, *oer.OAuthError) {
			username := r.FormValue("username")
			if username == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'username' parameter")
			}
			password := r.FormValue("password")
			if password == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'password' parameter")
			}
			// OPTIONAL
			scp_req := r.FormValue("scope")

			uid, err := sdi.FindUserId(username, password)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Error(log.TokenEndpointLog(TypePassword, log.InterfaceUnsupported,
						map[string]string{"method": "FindUserId"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			info, err := sdi.CreateOrUpdateAuthInfo(uid, c.Id(), scp_req, nil)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Error(log.TokenEndpointLog(TypePassword, log.InterfaceUnsupported,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {
					logger.Error(log.TokenEndpointLog(TypePassword, log.InterfaceError,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns (nil, nil)."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			token, err := sdi.CreateAccessToken(info,
				scope.IncludeOfflineAccess(info.Scope()))
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Error(log.TokenEndpointLog(TypePassword, log.InterfaceUnsupported,
						map[string]string{"method": "CreateAccessToken"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {
					logger.Error(log.TokenEndpointLog(TypePassword, log.InterfaceError,
						map[string]string{"method": "CreateAccessToken"},
						"the method returns (nil, nil)."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
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
