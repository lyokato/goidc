package assertion

import (
	"encoding/json"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lyokato/goidc/bridge"
	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
)

func HandleAssertionError(a string, t *jwt.Token, jwt_err error,
	gt string, c bridge.ClientInterface, sdi bridge.DataInterface,
	logger log.Logger) *oer.OAuthError {

	if jwt_err != nil {

		ve := jwt_err.(*jwt.ValidationError)

		if ve.Errors&jwt.ValidationErrorUnverifiable == jwt.ValidationErrorUnverifiable {

			// - invalid alg
			// - no key func
			// - key func returns err
			if inner, ok := ve.Inner.(*oer.OAuthError); ok {

				logger.Debug(log.TokenEndpointLog(gt,
					log.AssertionConditionMismatch,
					map[string]string{"assertion": a},
					"found OAuthError, so, returns it"))

				return inner

			} else {

				logger.Debug(log.TokenEndpointLog(gt,
					log.AssertionConditionMismatch,
					map[string]string{"assertion": a},
					"'assertion' unverifiable"))

				return oer.NewOAuthError(oer.ErrInvalidGrant,
					"assertion unverifiable")
			}
		}

		if ve.Errors&jwt.ValidationErrorMalformed == jwt.ValidationErrorMalformed {

			logger.Debug(log.TokenEndpointLog(gt,
				log.AssertionConditionMismatch,
				map[string]string{"assertion": a, "client_id": c.GetId()},
				"invalid 'assertion' format"))

			return oer.NewOAuthError(oer.ErrInvalidGrant,
				"invalid assertion format")
		}

		if ve.Errors&jwt.ValidationErrorSignatureInvalid == jwt.ValidationErrorSignatureInvalid {

			logger.Info(log.TokenEndpointLog(gt,
				log.AssertionConditionMismatch,
				map[string]string{"assertion": a, "client_id": c.GetId()},
				"invalid 'assertion' signature"))

			return oer.NewOAuthError(oer.ErrInvalidClient,
				"invalid assertion signature")

		}

		if ve.Errors&jwt.ValidationErrorExpired == jwt.ValidationErrorExpired {

			logger.Info(log.TokenEndpointLog(gt,
				log.AssertionConditionMismatch,
				map[string]string{"assertion": a, "client_id": c.GetId()},
				"assertion expired"))

			return oer.NewOAuthError(oer.ErrInvalidGrant,
				"assertion expired")
		}

		if ve.Errors&jwt.ValidationErrorNotValidYet == jwt.ValidationErrorNotValidYet {

			logger.Info(log.TokenEndpointLog(gt,
				log.AssertionConditionMismatch,
				map[string]string{"assertion": a, "client_id": c.GetId()},
				"assertion not valid yet"))

			return oer.NewOAuthError(oer.ErrInvalidGrant,
				"assertion not valid yet")
		}

		// unknown error type
		logger.Warn(log.TokenEndpointLog(gt,
			log.AssertionConditionMismatch,
			map[string]string{"assertion": a, "client_id": c.GetId()},
			"unknown 'assertion' validation failure"))

		return oer.NewOAuthError(oer.ErrInvalidGrant,
			"invalid assertion")
	}

	if !t.Valid {

		// must not come here
		logger.Warn(log.TokenEndpointLog(gt,
			log.AssertionConditionMismatch,
			map[string]string{"assertion": a, "client_id": c.GetId()},
			"invalid 'assertion' signature"))

		return oer.NewOAuthError(oer.ErrInvalidGrant,
			"invalid assertion signature")
	}

	var exp, iat int64
	exp_exists := false
	iat_exists := false
	jti := ""
	var er error
	switch num := t.Claims["exp"].(type) {
	case json.Number:
		if exp, er = num.Int64(); er == nil {
			exp_exists = true
		}
	case float64:
		exp_exists = true
		exp = int64(num)
	}

	if !exp_exists {

		logger.Debug(log.TokenEndpointLog(gt,
			log.MissingParam,
			map[string]string{"param": "exp", "client_id": c.GetId()},
			"'exp' not found in assertion"))

		return oer.NewOAuthError(oer.ErrInvalidRequest,
			"'exp' parameter not found in assertion")
	}

	switch num := t.Claims["iat"].(type) {
	case json.Number:
		if iat, er = num.Int64(); er == nil {
			iat_exists = true
		}
	case float64:
		iat_exists = true
		iat = int64(num)
	}
	if !iat_exists {
		iat = -1
	}

	if found, ok := t.Claims["jti"].(string); ok {
		jti = found
	}

	err := sdi.RecordAssertionClaims(c.GetId(), jti, iat, exp)
	if err != nil {
		if err.Type() == bridge.ErrFailed {

			logger.Info(log.TokenEndpointLog(gt,
				log.AssertionConditionMismatch,
				map[string]string{
					"method":    "RecordAssertionClaims",
					"client_id": c.GetId(),
					"jti":       jti,
					"exp":       fmt.Sprintf("%d", exp),
					"iat":       fmt.Sprintf("%d", iat),
					"assertion": a,
				},
				"failed to check with sub,jti,iat,exp"))

			return oer.NewOAuthSimpleError(oer.ErrInvalidRequest)

		} else if err.Type() == bridge.ErrUnsupported {

			logger.Error(log.TokenEndpointLog(gt,
				log.InterfaceUnsupported,
				map[string]string{
					"method":    "RecordAssertionClaims",
					"client_id": c.GetId(),
				},
				"the method returns 'unsupported' error."))

			return oer.NewOAuthSimpleError(oer.ErrServerError)

		} else {

			logger.Warn(log.TokenEndpointLog(gt,
				log.InterfaceServerError,
				map[string]string{
					"method":    "RecordAssertionClaims",
					"client_id": c.GetId(),
					"jti":       jti,
					"exp":       fmt.Sprintf("%d", exp),
					"iat":       fmt.Sprintf("%d", iat),
					"assertion": a,
				},
				"interface returned ServerError."))

			return oer.NewOAuthSimpleError(oer.ErrServerError)

		}
	}

	aud, ok := t.Claims["aud"].(string)
	if !ok {

		logger.Debug(log.TokenEndpointLog(gt,
			log.MissingParam,
			map[string]string{"param": "aud", "client_id": c.GetId()},
			"'aud' not found in assertion"))

		return oer.NewOAuthError(oer.ErrInvalidRequest,
			"'aud' parameter not found in assertion")
	}

	service := sdi.Issuer()
	if service == "" {

		logger.Error(log.TokenEndpointLog(gt,
			log.InterfaceUnsupported,
			map[string]string{"method": "Issure"},
			"the method returns 'unsupported' error."))

		return oer.NewOAuthSimpleError(oer.ErrServerError)
	}

	if aud != service {

		logger.Info(log.TokenEndpointLog(gt,
			log.AssertionConditionMismatch,
			map[string]string{"assertion": a, "client_id": c.GetId()},
			"invalid 'aud'"))

		return oer.NewOAuthError(oer.ErrInvalidGrant,
			fmt.Sprintf("invalid 'aud' parameter '%s' in assertion", aud))
	}

	return nil
}
