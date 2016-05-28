package grant

import (
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/lyokato/goidc/assertion"
	"github.com/lyokato/goidc/flow"
	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	sd "github.com/lyokato/goidc/service_data"
)

// RFC7523
// JSON Web Token (JWT) Profile
// for OAuth 2.0 Client Authentication and Authorization Grants

const TypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func JWT() *GrantHandler {
	return &GrantHandler{
		TypeJWT,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface, logger log.Logger) (*Response, *oer.OAuthError) {

			a := r.FormValue("assertion")
			if a == "" {

				logger.Debug(log.TokenEndpointLog(TypeJWT,
					log.MissingParam,
					map[string]string{"param": "assertion", "client_id": c.GetId()},
					"'assertion' not found"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'assertion' parameter")
			}

			t, jwt_err := jwt.Parse(a, func(t *jwt.Token) (interface{}, error) {

				alg := ""
				kid := ""

				if found, ok := t.Header["alg"].(string); ok {
					alg = found
				}
				if found, ok := t.Header["kid"].(string); ok {
					kid = found
				}

				key := c.GetAssertionKey(alg, kid)

				if key == nil {
					return nil, fmt.Errorf("key_not_found")
				} else {
					return key, nil
				}
			})

			oerr := assertion.HandleAssertionError(a, t, jwt_err, TypeJWT, c, sdi, logger)
			if oerr != nil {
				return nil, oerr
			}
			sub, ok := t.Claims["sub"].(string)
			if !ok {

				logger.Debug(log.TokenEndpointLog(TypeJWT,
					log.MissingParam,
					map[string]string{"param": "sub", "client_id": c.GetId()},
					"'sub' not found in assertion"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"'sub' parameter not found")
			}

			uid, err := sdi.FindUserIdBySubject(sub)
			if err != nil {
				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeJWT,
						log.NoEnabledUserId,
						map[string]string{
							"method":    "FindUserIdBySubject",
							"client_id": c.GetId(),
							"subject":   sub,
						},
						"user_id associated with this subject not found."))

					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						fmt.Sprintf("invalid 'sub' parameter '%s' in assertion", sub))

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeJWT,
						log.InterfaceUnsupported,
						map[string]string{"method": "FindUserIdBySubject"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeJWT,
						log.InterfaceServerError,
						map[string]string{"method": "FindUserIdBySubject", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			scp_req := r.FormValue("scope")
			if scp_req != "" && !c.CanUseScope(flow.DirectGrant, scp_req) {

				logger.Info(log.TokenEndpointLog(TypeJWT,
					log.InvalidScope,
					map[string]string{"scope": scp_req, "client_id": c.GetId()},
					"requested scope is not allowed to this client"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidScope)
			}

			info, err := sdi.CreateOrUpdateAuthInfo(uid, c.GetId(), scp_req)
			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeJWT,
						log.AuthInfoCreationFailed,
						map[string]string{"method": "CreateOrUpdateAuthInfo", "client_id": c.GetId()},
						"failed to create auth info."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeJWT,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeJWT,
						log.InterfaceServerError,
						map[string]string{"method": "CreateOrUpdateAuthInfo", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {

					logger.Error(log.TokenEndpointLog(TypeJWT,
						log.InterfaceError,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			token, err := sdi.CreateOAuthToken(info, true)

			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeJWT,
						log.AccessTokenCreationFailed,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"failed to create access token."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeJWT,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOAuthToken"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeJWT,
						log.InterfaceServerError,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				}
			} else {
				if token == nil {

					logger.Error(log.TokenEndpointLog(TypeJWT,
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
