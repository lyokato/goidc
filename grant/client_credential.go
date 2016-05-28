package grant

import (
	"net/http"

	"github.com/lyokato/goidc/authorizer"
	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	sd "github.com/lyokato/goidc/service_data"
)

const TypeClientCredentials = "client_credentials"

func ClientCredentials() *GrantHandler {
	return &GrantHandler{
		TypeClientCredentials,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface, logger log.Logger) (*Response, *oer.OAuthError) {

			uid := c.GetOwnerUserId()
			if uid < 0 {

				logger.Warn(log.TokenEndpointLog(TypeClientCredentials,
					log.NoEnabledUserId,
					map[string]string{"method": "OwnerUserId", "client_id": c.GetId()},
					"client returned no enabled owner's id"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
			}

			scp_req := r.FormValue("scope")
			if scp_req != "" && !c.CanUseScope(authorizer.FlowTypeDirectGrant, scp_req) {

				logger.Info(log.TokenEndpointLog(TypeClientCredentials,
					log.InvalidScope,
					map[string]string{"scope": scp_req, "client_id": c.GetId()},
					"requested scope is not allowed to this client"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidScope)
			}

			info, err := sdi.CreateOrUpdateAuthInfo(uid, c.GetId(), scp_req)
			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeClientCredentials,
						log.AuthInfoCreationFailed,
						map[string]string{"method": "CreateOrUpdateAuthInfo", "client_id": c.GetId()},
						"failed to create auth info."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeClientCredentials,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeClientCredentials,
						log.InterfaceServerError,
						map[string]string{"method": "CreateOrUpdateAuthInfo", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {

					logger.Error(log.TokenEndpointLog(TypeClientCredentials,
						log.InterfaceError,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			token, err := sdi.CreateOAuthToken(info, true)

			if err != nil {
				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeClientCredentials,
						log.AccessTokenCreationFailed,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"failed to create access token."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeClientCredentials,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOAuthToken"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeClientCredentials,
						log.InterfaceServerError,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {

					logger.Error(log.TokenEndpointLog(TypeClientCredentials,
						log.InterfaceError,
						map[string]string{"method": "CreateOAuthToken"},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			res := NewResponse(token.GetAccessToken(), token.GetAccessTokenExpiresIn())

			scp := info.GetScope()
			if scp != "" {
				res.Scope = scp
			}
			rt := token.GetRefreshToken()
			if rt != "" {
				res.RefreshToken = rt
			}
			return res, nil
		},
	}
}
