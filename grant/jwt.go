package grant

import (
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/scope"
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
					map[string]string{"param": "assertion", "client_id": c.Id()},
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

				key := c.AssertionKey(alg, kid)

				if key == nil {
					return nil, fmt.Errorf("key_not_found")
				} else {
					return key, nil
				}
			})

			if jwt_err != nil {

				ve := jwt_err.(*jwt.ValidationError)

				if ve.Errors&jwt.ValidationErrorMalformed == jwt.ValidationErrorMalformed {

					logger.Debug(log.TokenEndpointLog(TypeJWT,
						log.AssertionConditionMismatch,
						map[string]string{"assertion": a, "client_id": c.Id()},
						"invalid 'assertion' format"))

					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						"invalid assertion format")
				}

				if ve.Errors&jwt.ValidationErrorUnverifiable == jwt.ValidationErrorUnverifiable {

					// - invalid alg
					// - no key func
					// - key func returns err
					if inner, ok := ve.Inner.(*oer.OAuthError); ok {

						logger.Debug(log.TokenEndpointLog(TypeJWT,
							log.AssertionConditionMismatch,
							map[string]string{"assertion": a, "client_id": c.Id()},
							"'assertion' unverifiable"))

						return nil, inner
					} else {

						return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
							"assertion unverifiable")
					}
				}

				if ve.Errors&jwt.ValidationErrorSignatureInvalid == jwt.ValidationErrorSignatureInvalid {

					logger.Info(log.TokenEndpointLog(TypeJWT,
						log.AssertionConditionMismatch,
						map[string]string{"assertion": a, "client_id": c.Id()},
						"invalid 'assertion' signature"))

					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						"invalid assertion signature")

				}

				if ve.Errors&jwt.ValidationErrorExpired == jwt.ValidationErrorExpired {

					logger.Info(log.TokenEndpointLog(TypeJWT,
						log.AssertionConditionMismatch,
						map[string]string{"assertion": a, "client_id": c.Id()},
						"assertion expired"))

					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						"assertion expired")
				}

				if ve.Errors&jwt.ValidationErrorNotValidYet == jwt.ValidationErrorNotValidYet {

					logger.Info(log.TokenEndpointLog(TypeJWT,
						log.AssertionConditionMismatch,
						map[string]string{"assertion": a, "client_id": c.Id()},
						"assertion not valid yet"))

					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						"assertion not valid yet")
				}

				// unknown error type
				logger.Warn(log.TokenEndpointLog(TypeJWT,
					log.AssertionConditionMismatch,
					map[string]string{"assertion": a, "client_id": c.Id()},
					"unknown 'assertion' validation failure"))

				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					"invalid assertion")
			}

			if !t.Valid {

				// must not come here
				logger.Warn(log.TokenEndpointLog(TypeJWT,
					log.AssertionConditionMismatch,
					map[string]string{"assertion": a, "client_id": c.Id()},
					"invalid 'assertion' signature"))

				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					"invalid assertion signature")
			}

			// MUST(exp) error
			// MAY(iat) reject if too far past
			// MAY(jti)

			aud, ok := t.Claims["aud"].(string)
			if !ok {

				logger.Debug(log.TokenEndpointLog(TypeJWT,
					log.MissingParam,
					map[string]string{"param": "aud", "client_id": c.Id()},
					"'aud' not found in assertion"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"'aud' parameter not found in assertion")
			}

			service := sdi.Issuer()
			if service == "" {

				logger.Error(log.TokenEndpointLog(TypeJWT,
					log.InterfaceUnsupported,
					map[string]string{"method": "Issure"},
					"the method returns 'unsupported' error."))

				return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
			}

			if aud != service {

				logger.Info(log.TokenEndpointLog(TypeJWT,
					log.AssertionConditionMismatch,
					map[string]string{"assertion": a, "client_id": c.Id()},
					"invalid 'aud'"))

				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					fmt.Sprintf("invalid 'aud' parameter '%s' in assertion", aud))
			}

			sub, ok := t.Claims["sub"].(string)
			if !ok {

				logger.Debug(log.TokenEndpointLog(TypeJWT,
					log.MissingParam,
					map[string]string{"param": "sub", "client_id": c.Id()},
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
							"client_id": c.Id(),
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
						map[string]string{"method": "FindUserIdBySubject", "client_id": c.Id()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			scp_req := r.FormValue("scope")
			if scp_req != "" && !c.CanUseScope(scp_req) {

				logger.Info(log.TokenEndpointLog(TypeJWT,
					log.InvalidScope,
					map[string]string{"scope": scp_req, "client_id": c.Id()},
					"requested scope is not allowed to this client"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidScope)
			}

			info, err := sdi.CreateOrUpdateAuthInfo(uid, c.Id(), scp_req, nil)
			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeJWT,
						log.AuthInfoCreationFailed,
						map[string]string{"method": "CreateOrUpdateAuthInfo", "client_id": c.Id()},
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
						map[string]string{"method": "CreateOrUpdateAuthInfo", "client_id": c.Id()},
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

			token, err := sdi.CreateAccessToken(info,
				scope.IncludeOfflineAccess(info.Scope()))

			if err != nil {

				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeJWT,
						log.AccessTokenCreationFailed,
						map[string]string{"method": "CreateAccessToken", "client_id": c.Id()},
						"failed to create access token."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeJWT,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateAccessToken"},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeJWT,
						log.InterfaceServerError,
						map[string]string{"method": "CreateAccessToken", "client_id": c.Id()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				}
			} else {
				if token == nil {

					logger.Error(log.TokenEndpointLog(TypeJWT,
						log.InterfaceError,
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
