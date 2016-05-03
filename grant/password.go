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
					logger.Warnf("[goidc.TokenEndpoint:%s] <ServerError:InterfaceUnsupported:%s>: the method returns 'unsupported' error.",
						TypePassword, "FindUserId")
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			info, err := sdi.CreateOrUpdateAuthInfoDirect(uid, c.Id(), scp_req)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Warnf("[goidc.TokenEndpoint:%s] <ServerError:InterfaceUnsupported:%s>: the method returns 'unsupported' error.",
						TypePassword, "CreateOrUpdateAuthInfoDirect")
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {
					logger.Warnf("[goidc.TokenEndpoint:%s] <ServerError:InterfaceError:%s>: the method returns (nil, nil).",
						TypePassword, "CreateOrUpdateAuthInfoDirect")
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			token, err := sdi.CreateAccessToken(info,
				scope.IncludeOfflineAccess(info.Scope()))
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Warnf("[goidc.TokenEndpoint:%s] <ServerError:InterfaceUnsupported:%s>: the method returns 'unsupported' error.",
						TypePassword, "CreateAccessToken")
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {
					logger.Warnf("[goidc.TokenEndpoint:%s] <ServerError:InterfaceError:%s>: the method returns (nil, nil).",
						TypePassword, "CreateAccessToken")
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
