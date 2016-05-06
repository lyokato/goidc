package goidc

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/lyokato/goidc/assertion"
	"github.com/lyokato/goidc/grant"
	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	sd "github.com/lyokato/goidc/service_data"
)

var defaultResponseHeaders = map[string]string{
	"Cache-Control": "no-store",
	"Pragma":        "no-cache",
	"Content-Type":  "application/json; charset=UTF-8",
}

type TokenEndpoint struct {
	realm           string
	logger          log.Logger
	handlers        map[string]grant.GrantHandlerFunc
	errorURIBuilder oer.OAuthErrorURIBuilder
}

func (te *TokenEndpoint) SetLogger(l log.Logger) {
	te.logger = l
}

func (te *TokenEndpoint) SetErrorURI(uri string) {
	te.errorURIBuilder = func(_ oer.OAuthErrorType) string { return uri }
}

func (te *TokenEndpoint) SetErrorURIBuilder(builder oer.OAuthErrorURIBuilder) {
	te.errorURIBuilder = builder
}

func NewTokenEndpoint(realm string) *TokenEndpoint {
	return &TokenEndpoint{
		realm:    realm,
		logger:   log.NewDefaultLogger(),
		handlers: make(map[string]grant.GrantHandlerFunc),
	}
}

func (te *TokenEndpoint) Support(handler *grant.GrantHandler) {
	te.handlers[handler.Type] = handler.Func
}

func (te *TokenEndpoint) Handler(sdi sd.ServiceDataInterface) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != "POST" {

			te.logger.Debug(log.TokenEndpointLog("common", log.InvalidHTTPMethod,
				map[string]string{"http_method": r.Method},
				"http method is not POST"))

			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		gt := r.FormValue("grant_type")
		if gt == "" {

			te.logger.Debug(log.TokenEndpointLog("common", log.MissingParam,
				map[string]string{"param": "grant_type"},
				"'grant_type' not found"))

			te.fail(w, oer.NewOAuthError(oer.ErrInvalidRequest,
				"missing 'grant_type' parameter"))
			return
		}
		h, exists := te.handlers[gt]
		if !exists {

			te.logger.Debug(log.TokenEndpointLog("common", log.UnsupportedGrantType,
				map[string]string{"grant_type": gt},
				"unsupported 'grant_type'"))

			te.fail(w, oer.NewOAuthError(oer.ErrUnsupportedGrantType,
				fmt.Sprintf("unsupported 'grant_type' parameter: '%s'", gt)))
			return
		}
		cid, sec, inHeader, exists := te.findClientCredential(r)
		if exists {
			client, ok := te.validateClientBySecret(w, r,
				sdi, gt, cid, sec, inHeader)
			if ok {
				te.executeGrantHandler(w, r, sdi, client, gt, h)
			}
			return
		}
		ca, exists := te.findClientAssertion(r)
		if exists {
			client, ok := te.validateClientByAssertion(w, r,
				sdi, gt, ca)
			if ok {
				te.executeGrantHandler(w, r, sdi, client, gt, h)
			}
			return
		}

		te.logger.Debug(log.TokenEndpointLog(gt, log.NoCredential,
			map[string]string{"grant_type": gt},
			"credential information not found."))

		te.failWithAuthHeader(w,
			oer.NewOAuthSimpleError(oer.ErrInvalidClient))
		return

	}
}

func (te *TokenEndpoint) validateClientByAssertion(w http.ResponseWriter,
	r *http.Request, sdi sd.ServiceDataInterface,
	gt, ca string) (sd.ClientInterface, bool) {

	// RFC7523
	// JSON Web Token (JWT) Profile
	// for OAuth 2.0 Client Authentication and Authorization Grants

	var c sd.ClientInterface
	t, jwt_err := jwt.Parse(ca, func(t *jwt.Token) (interface{}, error) {

		cid := ""
		if found, ok := t.Claims["sub"].(string); ok {
			cid = found
		} else {

			te.logger.Debug(log.TokenEndpointLog(gt,
				log.MissingParam,
				map[string]string{"assertion": ca},
				"'sub' not found in assertion"))

			return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
				"'sub' parameter not found in assertion")
		}

		var serr *sd.Error
		c, serr = sdi.FindClientById(cid)

		if serr != nil {

			if serr.Type() == sd.ErrFailed {

				te.logger.Info(log.TokenEndpointLog(gt,
					log.NoEnabledClient,
					map[string]string{
						"method":    "FindClientById",
						"assertion": ca,
						"client_id": cid,
					},
					"client associated with the sub value in assertion not found"))

				return nil, oer.NewOAuthSimpleError(oer.ErrInvalidClient)

			} else if serr.Type() == sd.ErrUnsupported {

				te.logger.Error(log.TokenEndpointLog(gt,
					log.InterfaceUnsupported,
					map[string]string{"method": "FindClientById"},
					"the method returns 'unsupported' error."))

				return nil, oer.NewOAuthSimpleError(oer.ErrServerError)

			} else {

				te.logger.Warn(log.TokenEndpointLog(gt,
					log.InterfaceServerError,
					map[string]string{
						"method":    "FindClientById",
						"assertion": ca,
						"client_id": cid,
					},
					"interface returned ServerError"))

				return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
			}

		} else {
			if c == nil {

				te.logger.Error(log.TokenEndpointLog(gt,
					log.InterfaceError,
					map[string]string{
						"method":    "FindClientById",
						"assertion": ca,
						"client_id": cid,
					},
					"the method returns (nil, nil)."))

				return nil, oer.NewOAuthSimpleError(oer.ErrServerError)
			}
		}

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

			te.logger.Debug(log.TokenEndpointLog(gt,
				log.MissingParam,
				map[string]string{
					"assertion": ca,
					"method":    "AssertionKey",
				},
				"returns nil as key"))

			return nil, fmt.Errorf("key_not_found")
		} else {
			return key, nil
		}
	})

	err := assertion.HandleAssertionError(ca, t, jwt_err, gt, c, sdi, te.logger)
	if err != nil {
		te.fail(w, err)
		return nil, false
	}

	return c, true
}

func (te *TokenEndpoint) validateClientBySecret(w http.ResponseWriter,
	r *http.Request, sdi sd.ServiceDataInterface, gt, cid, sec string,
	inHeader bool) (sd.ClientInterface, bool) {

	client, err := sdi.FindClientById(cid)

	if err != nil {
		if err.Type() == sd.ErrFailed {

			te.logger.Debug(log.TokenEndpointLog(gt, log.NoEnabledClient,
				map[string]string{"method": "FindClientById", "client_id": cid},
				"client not found."))

			te.failByInvalidClientError(w, inHeader)
			return nil, false

		} else if err.Type() == sd.ErrUnsupported {

			te.logger.Error(log.TokenEndpointLog(gt, log.InterfaceUnsupported,
				map[string]string{"method": "FindClientById"},
				"the method returns 'unsupported' error."))

			te.fail(w, oer.NewOAuthSimpleError(oer.ErrServerError))
			return nil, false

		} else {
			te.logger.Warn(log.TokenEndpointLog(gt, log.InterfaceServerError,
				map[string]string{"method": "FindClientById", "client_id": cid},
				"interface returned ServerError"))

			te.fail(w, oer.NewOAuthSimpleError(oer.ErrServerError))
			return nil, false
		}
	} else {
		if client == nil {

			te.logger.Error(log.TokenEndpointLog(gt, log.InterfaceError,
				map[string]string{"method": "FindClientById", "client_id": cid},
				"the method returns (nil, nil)."))

			te.fail(w, oer.NewOAuthSimpleError(oer.ErrServerError))
			return nil, false
		}
	}
	if !client.MatchSecret(sec) {

		te.logger.Info(log.TokenEndpointLog(gt, log.AuthenticationFailed,
			map[string]string{
				"client_id":       cid,
				"remote_addr":     r.Header.Get("REMOTE_ADDR"),
				"x-forwarded-for": r.Header.Get("X-FORWARDED-FOR"),
			}, "'client_secret' mismatch."))

		te.failByInvalidClientError(w, inHeader)
		return nil, false
	}
	if !client.CanUseGrantType(gt) {

		te.logger.Info(log.TokenEndpointLog(gt, log.UnauthorizedGrantType,
			map[string]string{"client_id": cid}, "unauthorized 'grant_type'."))

		te.fail(w, oer.NewOAuthSimpleError(oer.ErrUnauthorizedClient))
		return nil, false
	}

	return client, true
}

func (te *TokenEndpoint) executeGrantHandler(w http.ResponseWriter,
	r *http.Request, sdi sd.ServiceDataInterface,
	client sd.ClientInterface, gt string, h grant.GrantHandlerFunc) {
	res, oerr := h(r, client, sdi, te.logger)
	if oerr != nil {
		te.fail(w, oerr)
		return
	} else {
		te.logger.Debug(log.TokenEndpointLog(gt, log.AccessTokenGranted,
			map[string]string{"client_id": client.Id()},
			"granted successfully"))
		te.success(w, res)
		return
	}
}

func (te *TokenEndpoint) failByInvalidClientError(w http.ResponseWriter, inHeader bool) {
	if inHeader {
		te.failWithAuthHeader(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
	} else {
		te.fail(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
	}
}

func (te *TokenEndpoint) findClientCredential(r *http.Request) (string, string, bool, bool) {
	cid, sec, exists := r.BasicAuth()
	if exists {
		return cid, sec, true, true
	}
	cid = r.FormValue("client_id")
	sec = r.FormValue("client_secret")
	if cid != "" && sec != "" {
		return cid, sec, false, true
	} else {
		return "", "", false, false
	}
}

func (te *TokenEndpoint) findClientAssertion(r *http.Request) (string, bool) {
	ca := r.FormValue("client_assertion")
	cat := r.FormValue("client_assertion_type")
	if ca != "" && cat == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return ca, true
	} else {
		return "", false
	}
}

func setCommonResponseHeader(w http.ResponseWriter) {
	for k, v := range defaultResponseHeaders {
		w.Header().Set(k, v)
	}
}

func (te *TokenEndpoint) success(w http.ResponseWriter, res *grant.Response) {
	setCommonResponseHeader(w)
	w.WriteHeader(http.StatusOK)
	w.Write(res.JSON())
}

func (te *TokenEndpoint) failWithAuthHeader(w http.ResponseWriter, err *oer.OAuthError) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", te.realm))
	setCommonResponseHeader(w)
	if err.URI == "" && te.errorURIBuilder != nil {
		err.URI = te.errorURIBuilder(err.Type)
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(err.JSON())
}

func (te *TokenEndpoint) fail(w http.ResponseWriter, err *oer.OAuthError) {
	setCommonResponseHeader(w)
	if err.URI == "" && te.errorURIBuilder != nil {
		err.URI = te.errorURIBuilder(err.Type)
	}
	w.WriteHeader(err.StatusCode())
	w.Write(err.JSON())
}
