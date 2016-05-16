package grant

import (
	"net/http"

	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
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

				logger.Debug(log.TokenEndpointLog(TypePassword,
					log.MissingParam,
					map[string]string{"param": "username", "client_id": c.GetId()},
					"'username' not found"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'username' parameter")
			}

			password := r.FormValue("password")
			if password == "" {

				logger.Debug(log.TokenEndpointLog(TypePassword,
					log.MissingParam,
					map[string]string{"param": "password", "client_id": c.GetId()},
					"'password' not found"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'password' parameter")
			}

			scp_req := r.FormValue("scope")
			if scp_req != "" && !c.CanUseScope(scp_req) {

				logger.Info(log.TokenEndpointLog(TypePassword, log.InvalidScope,
					map[string]string{"scope": scp_req, "client_id": c.GetId()},
					"requested scope is not allowed to this client"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidScope)
			}

			uid, err := sdi.FindUserId(username, password)
			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypePassword,
						log.NoEnabledUserId,
						map[string]string{
							"method":    "FindUserId",
							"client_id": c.GetId(),
							"username":  username,
							"password":  password,
						},
						"user id not found."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypePassword,
						log.InterfaceUnsupported,
						map[string]string{"method": "FindUserId"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypePassword,
						log.InterfaceServerError,
						map[string]string{
							"method":    "FindUserId",
							"client_id": c.GetId(),
							"username":  username,
							"password":  password,
						},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			info, err := sdi.CreateOrUpdateAuthInfo(uid, c.GetId(), scp_req, nil)
			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypePassword,
						log.AuthInfoCreationFailed,
						map[string]string{
							"method":    "CreateOrUpdateAuthInfo",
							"client_id": c.GetId(),
						},
						"user id not found."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypePassword,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypePassword,
						log.InterfaceServerError,
						map[string]string{
							"method":    "CreateOrUpdateAuthInfo",
							"client_id": c.GetId(),
						},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {

					logger.Error(log.TokenEndpointLog(TypePassword,
						log.InterfaceError,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			token, err := sdi.CreateOAuthToken(info)

			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypePassword,
						log.AccessTokenCreationFailed,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"failed to create access token."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypePassword,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOAuthToken"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypePassword,
						log.InterfaceServerError,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {

					logger.Error(log.TokenEndpointLog(TypePassword,
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
