package goidc

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyokato/goidc/log"
	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/scope"
	sd "github.com/lyokato/goidc/service_data"
)

type ResourceProtector struct {
	realm                 string
	logger                log.Logger
	errorURIBuilder       oer.OAuthErrorURIBuilder
	tokenAcceptanceMethod CredentialAcceptanceMethod
}

func NewResourceProtector(realm string) *ResourceProtector {
	return &ResourceProtector{
		realm:                 realm,
		logger:                log.NewDefaultLogger(),
		tokenAcceptanceMethod: FromHeader,
	}
}

func (rp *ResourceProtector) AcceptAccessToken(meth CredentialAcceptanceMethod) {
	rp.tokenAcceptanceMethod = meth
}

func (rp *ResourceProtector) SetLogger(l log.Logger) {
	rp.logger = l
}

func (rp *ResourceProtector) SetErrorURI(uri string) {
	rp.errorURIBuilder = func(_ oer.OAuthErrorType) string { return uri }
}

func (rp *ResourceProtector) SetErrorURIBulder(builder oer.OAuthErrorURIBuilder) {
	rp.errorURIBuilder = builder
}

func (rp *ResourceProtector) findTokenFromRequest(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.Split(header, " ")
	if len(parts) < 2 {
		return ""
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	token := parts[1]
	if token != "" {
		return token
	}
	switch rp.tokenAcceptanceMethod {
	case FromHeader:
		return ""
	case FromHeaderAndPostBody:
		return r.PostFormValue("access_token")
	case FromAll:
		return r.FormValue("access_token")
	default:
		return ""
	}
}

func (rp *ResourceProtector) ValidateWithScopes(w http.ResponseWriter, r *http.Request,
	sdi sd.ServiceDataInterface, scopeMap map[string][]string) bool {

	if !rp.Validate(w, r, sdi) {
		return false
	}

	if scopes, exists := scopeMap[r.URL.Path]; exists {
		s := r.Header.Get("X-OAUTH-SCOPE")
		ok, not_found := scope.IncludeAll(s, scopes)
		if ok {
			return true
		} else {
			rp.unauthorize(w, oer.NewOAuthError(oer.ErrInsufficientScope,
				fmt.Sprintf("this endpoint requires %s scope, but the access_token was't issued for.",
					strconv.Quote(not_found))))
			return false
		}
	} else {
		return true
	}
}

func (rp *ResourceProtector) Validate(w http.ResponseWriter, r *http.Request,
	sdi sd.ServiceDataInterface) bool {

	rt := rp.findTokenFromRequest(r)

	if rt == "" {

		rp.logger.Debug(log.TokenEndpointLog(r.URL.Path,
			log.NoCredential,
			map[string]string{},
			"access_token not found in request."))

		rp.unauthorize(w, oer.NewOAuthSimpleError(oer.ErrInvalidRequest))
		return false
	}

	at, err := sdi.FindOAuthTokenByAccessToken(rt)

	if err != nil {
		if err.Type() == sd.ErrFailed {

			rp.logger.Info(log.ProtectedResourceLog(r.URL.Path,
				log.AuthenticationFailed,
				map[string]string{
					"access_token":    rt,
					"remote_addr":     r.Header.Get("REMOTE_ADDR"),
					"x-forwarded-for": r.Header.Get("X-FORWARDED-FOR"),
				}, "'access_token' not found."))

			rp.unauthorize(w, oer.NewOAuthSimpleError(oer.ErrInvalidToken))
			return false

		} else if err.Type() == sd.ErrUnsupported {

			rp.logger.Error(log.ProtectedResourceLog(r.URL.Path,
				log.InterfaceUnsupported,
				map[string]string{"method": "FindAccessTokenByAccessToken"},
				"the method returns 'unsupported' error."))

			w.WriteHeader(http.StatusInternalServerError)
			return false

		} else {

			rp.logger.Warn(log.ProtectedResourceLog(r.URL.Path,
				log.InterfaceServerError,
				map[string]string{
					"method":       "FindAccessTokenByAccessToken",
					"access_token": rt,
				},
				"interface returned ServerError."))

			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
	} else {
		if at == nil {

			rp.logger.Error(log.ProtectedResourceLog(r.URL.Path, log.InterfaceError,
				map[string]string{"method": "FindAccessTokenByAccessToken"},
				"the method returns (nil, nil)."))

			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
	}

	if at.RefreshedAt()+at.AccessTokenExpiresIn() < time.Now().Unix() {
		rp.unauthorize(w, oer.NewOAuthError(oer.ErrInvalidToken,
			"your access_token is expired"))
		return false
	}

	info, err := sdi.FindAuthInfoById(at.AuthId())
	if err != nil {
		if err.Type() == sd.ErrFailed {

			rp.logger.Debug(log.TokenEndpointLog(r.URL.Path,
				log.NoEnabledAuthInfo,
				map[string]string{
					"method":       "FindAuthInfoById",
					"access_token": rt,
				},
				"no enabled auth info associated with this access_token."))

			rp.unauthorize(w, oer.NewOAuthSimpleError(oer.ErrInvalidToken))
			return false

		} else if err.Type() == sd.ErrUnsupported {

			rp.logger.Error(log.ProtectedResourceLog(r.URL.Path,
				log.InterfaceUnsupported,
				map[string]string{"method": "FindAuthInfoById"},
				"the method returns 'unsupported' error."))

			w.WriteHeader(http.StatusInternalServerError)
			return false

		} else {

			rp.logger.Warn(log.TokenEndpointLog(r.URL.Path,
				log.InterfaceServerError,
				map[string]string{
					"method":       "FindAuthInfoById",
					"access_token": rt,
				},
				"interface returned ServerError"))

			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
	} else {
		if at == nil {

			rp.logger.Error(log.ProtectedResourceLog(r.URL.Path, log.InterfaceError,
				map[string]string{"method": "FindClientById"},
				"the method returns (nil, nil)."))

			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
	}

	r.Header.Set("REMOTE_USER", fmt.Sprintf("%d", info.UserId()))
	r.Header.Set("X-OAUTH-CLIENT-ID", info.ClientId())
	r.Header.Set("X-OAUTH-SCOPE", info.Scope())

	return true
}

func (rp *ResourceProtector) unauthorize(w http.ResponseWriter, err *oer.OAuthError) {
	if err.URI == "" && rp.errorURIBuilder != nil {
		err.URI = rp.errorURIBuilder(err.Type)
	}
	w.Header().Set("WWW-Authenticate", err.Header(rp.realm))
	w.WriteHeader(err.StatusCode())
}
