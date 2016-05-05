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
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'assertion' parameter")
			}

			t, jwt_err := jwt.Parse(a, func(t *jwt.Token) (interface{}, error) {
				alg := t.Header["alg"].(string)
				kid := t.Header["kid"].(string)
				key := c.AssertionKey(alg, kid)
				if key == nil {
					return nil, fmt.Errorf("key_not_found")
				} else {
					return key, nil
				}
			})

			if !t.Valid {
				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					"invalid assertion signature")
			}

			if jwt_err != nil {

				// MUST(exp) error
				// MAY(nbf) error

			}

			// MAY(iat) reject if too far past
			// MAY(jti)

			aud, ok := t.Claims["aud"].(string)
			if !ok {
				// not found
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"'aud' parameter not found")
			}

			service := sdi.Issure()
			if service == "" {
				// server error
			}

			if aud != service {
				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					fmt.Sprintf("invalid 'aud' parameter '%s' in assertion", aud))
			}

			sub, ok := t.Claims["sub"].(string)
			if !ok {
				// not found
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"'sub' parameter not found")
			}

			uid, err := sdi.FindUserIdBySubject(sub)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						fmt.Sprintf("invalid 'sub' parameter '%s' in assertion", sub))
				} else {
					// server error
				}
			}

			scp_req := r.FormValue("scope")
			if scp_req != "" && !c.CanUseScope(scp_req) {
				logger.Info(log.TokenEndpointLog(TypeJWT, log.InvalidScope,
					map[string]string{"scope": scp_req, "client_id": c.Id()},
					"requested scope is not allowed to this client"))
				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidScope)
			}

			info, err := sdi.CreateOrUpdateAuthInfo(uid, c.Id(), scp_req, nil)
			if err != nil {
				if err.Type() == sd.ErrFailed {
					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
				} else if err.Type() == sd.ErrUnsupported {
					logger.Error(log.TokenEndpointLog(TypeJWT, log.InterfaceUnsupported,
						map[string]string{"method": "CreateOrUpdateAuthInfo"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {
					logger.Error(log.TokenEndpointLog(TypeJWT, log.InterfaceError,
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
					logger.Error(log.TokenEndpointLog(TypeJWT, log.InterfaceUnsupported,
						map[string]string{"method": "CreateAccessToken"},
						"the method returns 'unsupported' error."))
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				} else {
					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {
					logger.Error(log.TokenEndpointLog(TypeJWT, log.InterfaceError,
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
