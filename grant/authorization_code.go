package grant

import (
	"fmt"
	"net/http"

	"github.com/lyokato/goidc/id_token"

	"github.com/lyokato/goidc/scope"

	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/pkce"
	sd "github.com/lyokato/goidc/service_data"
)

const TypeAuthorizationCode = "authorization_code"

func AuthorizationCode() *GrantHandler {
	return &GrantHandler{
		TypeAuthorizationCode,
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface, logger log.Logger) (*Response, *oer.OAuthError) {

			uri := r.FormValue("redirect_uri")
			if uri == "" {

				logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
					log.MissingParam,
					map[string]string{"param": "redirect_uri", "client_id": c.GetId()},
					"'redirect_uri' not found"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'redirect_uri' parameter")
			}
			code := r.FormValue("code")
			if code == "" {

				logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
					log.MissingParam,
					map[string]string{"param": "code", "client_id": c.GetId()},
					"'code' not found"))

				return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
					"missing 'code' parameter")
			}

			sess, err := sdi.FindAuthSessionByCode(code)
			if err != nil {
				if err.Type() == sd.ErrFailed {

					logger.Info(log.TokenEndpointLog(TypeAuthorizationCode,
						log.NoEnabledAuthSession,
						map[string]string{
							"method":    "FindAuthSessionByCode",
							"code":      code,
							"client_id": c.GetId(),
						},
						"enabled AuthSession associated with the code not found."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceUnsupported,
						map[string]string{"method": "FindAuthSessionByCode", "client_id": c.GetId()},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceServerError,
						map[string]string{
							"method":    "FindAuthSessionByCode",
							"code":      code,
							"client_id": c.GetId(),
						},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if sess == nil {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceError,
						map[string]string{"method": "FindAuthSessionByCode", "client_id": c.GetId()},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}
			info, err := sdi.FindActiveAuthInfoById(sess.GetAuthId())
			if err != nil {
				if err.Type() == sd.ErrFailed {

					logger.Info(log.TokenEndpointLog(TypeAuthorizationCode,
						log.NoEnabledAuthInfo,
						map[string]string{
							"method":    "FindActiveAuthInfoById",
							"code":      code,
							"client_id": c.GetId(),
						},
						"enabled AuthInfo associated with the session not found."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceUnsupported,
						map[string]string{
							"method":    "FindActiveAuthInfoById",
							"client_id": c.GetId(),
						},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceServerError,
						map[string]string{
							"method":    "FindActiveAuthInfoById",
							"code":      code,
							"client_id": c.GetId(),
						},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if info == nil {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceError,
						map[string]string{
							"method":    "FindActiveAuthInfoById",
							"client_id": c.GetId(),
						},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}
			if info.GetClientId() != c.GetId() {

				logger.Info(log.TokenEndpointLog(TypeAuthorizationCode,
					log.AuthInfoConditionMismatch,
					map[string]string{"client_id": c.GetId()},
					"'client_id' mismatch"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)
			}
			if sess.GetRedirectURI() != uri {

				logger.Info(log.TokenEndpointLog(TypeAuthorizationCode,
					log.AuthInfoConditionMismatch,
					map[string]string{"client_id": c.GetId()},
					"'redirect_uri' mismatch"))

				return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
					fmt.Sprintf("indicated 'redirect_uri' (%s) is not allowed for this client", uri))
			}

			// RFC7636: OAuth PKCE Extension
			// https://tools.ietf.org/html/rfc7636
			cv := sess.GetCodeVerifier()
			if cv != "" {

				cm := r.FormValue("code_challenge_method")
				if cm == "" {

					logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
						log.MissingParam,
						map[string]string{
							"param":     "code_challenge_method",
							"client_id": c.GetId(),
						},
						"'code_challenge_method' not found"))

					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						"missing 'code_challenge_method' parameter")
				}
				cc := r.FormValue("code_challenge")
				if cc == "" {

					logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
						log.MissingParam,
						map[string]string{
							"param":     "code_challenge",
							"client_id": c.GetId(),
						},
						"'code_challenge' not found"))

					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						"missing 'code_challenge' parameter")
				}

				verifier, err := pkce.FindVerifierByMethod(cm)
				if err != nil {

					logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
						log.UnsupportedCodeChallengeMethod,
						map[string]string{
							"code_challenge_method": cm,
							"client_id":             c.GetId(),
						},
						"unsupported 'code_challenge_method'"))

					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						fmt.Sprintf("unsupported 'code_challenge_method': '%s'", cm))
				}
				if !verifier.Verify(cc, cv) {

					logger.Info(log.TokenEndpointLog(TypeAuthorizationCode,
						log.CodeChallengeFailed,
						map[string]string{
							"code_challenge_method": cm,
							"code_challenge":        cc,
							"client_id":             c.GetId(),
						},
						"failed code challenge"))

					return nil, oer.NewOAuthError(oer.ErrInvalidGrant,
						fmt.Sprintf("invalid 'code_challenge': '%s'", cc))
				}
			}

			token, err := sdi.CreateOAuthToken(info, true)

			if err != nil {
				if err.Type() == sd.ErrFailed {

					logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
						log.AccessTokenCreationFailed,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"failed to create access token."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceUnsupported,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceServerError,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"interface returned ServerError."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			} else {
				if token == nil {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode, log.InterfaceError,
						map[string]string{"method": "CreateOAuthToken", "client_id": c.GetId()},
						"the method returns (nil, nil)."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
				}
			}

			err = sdi.DisableSession(sess)
			if err != nil {
				if err.Type() == sd.ErrFailed {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.DisableSessionFailed,
						map[string]string{"method": "DisableSession", "client_id": c.GetId()},
						"failed to disable code."))

					return nil, oer.NewOAuthSimpleError(oer.ErrInvalidGrant)

				} else if err.Type() == sd.ErrUnsupported {

					logger.Error(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceUnsupported,
						map[string]string{"method": "DisableCode", "client_id": c.GetId()},
						"the method returns 'unsupported' error."))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {

					logger.Warn(log.TokenEndpointLog(TypeAuthorizationCode,
						log.InterfaceServerError,
						map[string]string{"method": "DisableCode", "client_id": c.GetId()},
						"interface returned ServerError."))

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

			if scope.IncludeOpenID(scp) {

				logger.Debug(log.TokenEndpointLog(TypeAuthorizationCode,
					log.IdTokenGeneration,
					map[string]string{"client_id": c.GetId()},
					"found 'openid' scope, so generate id_token, and attach it to response"))

				idt, err := id_token.Gen(
					c.GetIdTokenAlg(),
					c.GetIdTokenKey(),
					c.GetIdTokenKeyId(),
					sdi.Issuer(),
					info.GetClientId(),
					info.GetSubject(),
					sess.GetNonce(),
					sess.GetIdTokenExpiresIn(),
					sess.GetAuthTime(),
				)

				if err != nil {

					logger.Warn(log.TokenEndpointLog(TypeAuthorizationCode,
						log.IdTokenGeneration,
						map[string]string{"client_id": c.GetId()},
						fmt.Sprintf("failedd to generate id_token: %s", err)))

					return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

				} else {
					res.IdToken = idt
				}
			}
			return res, nil
		},
	}
}
