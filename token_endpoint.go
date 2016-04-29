package goidc

import (
	"net/http"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	oer "github.com/lyokato/goidc/oauth_error"
	sd "github.com/lyokato/goidc/service_data"
)

var defaultResponseHeaders = map[string]string{
	"Cache-Control": "no-store",
	"Pragma":        "no-cache",
	"Content-Type":  "application/json; charset=UTF-8",
}

type TokenEndpoint struct {
	handlers        map[string]grant.GrantHandlerFunc
	errorURIBuilder oer.OAuthErrorURIBuilder
}

func (te *TokenEndpoint) SetErrorURI(uri string) {
	te.errorURIBuilder = func(_ string) string { return uri }
}

func (te *TokenEndpoint) SetErrorURIBulder(builder oer.OAuthErrorURIBuilder) {
	te.errorURIBuilder = builder
}

func NewTokenEndpoint() *TokenEndpoint {
	return &TokenEndpoint{
		handlers: make(map[string]grant.GrantHandlerFunc),
	}
}

func (te *TokenEndpoint) Support(handler *grant.GrantHandler) {
	te.handlers[handler.Type] = handler.Func
}

func (te *TokenEndpoint) Handler(sdi sd.ServiceDataInterface) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		gt := r.FormValue("grant_type")
		if gt == "" {
			te.fail(w, oer.NewOAuthError(oer.ErrInvalidRequest, "", ""))
			return
		}
		if h, exists := te.handlers[gt]; exists {
			if cid, sec, exists := basic_auth.FindClientCredential(r); exists {
				client, err := sdi.FindValidClient(cid, sec, gt)
				if err != nil {
					switch err.Type {
					case oer.ErrUnauthorizedClient:
						te.fail(w, err)
					case oer.ErrServerError:
						te.fail(w, err)
					default:
						te.fail(w, oer.NewOAuthError(oer.ErrServerError, "", ""))
					}
					return
				}
				res, err := h(r, client, sdi)
				if err != nil {
					te.fail(w, err)
					return
				} else {
					te.success(w, res)
					return
				}
			} else {
				te.fail(w, oer.NewOAuthError(oer.ErrInvalidRequest, "", ""))
				return
			}
		} else {
			te.fail(w, oer.NewOAuthError(oer.ErrUnsupportedGrantType, "", ""))
			return
		}
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

func (te *TokenEndpoint) fail(w http.ResponseWriter, err *oer.OAuthError) {
	setCommonResponseHeader(w)
	if err.URI == "" && te.errorURIBuilder != nil {
		err.URI = te.errorURIBuilder(err.Type)
	}
	w.WriteHeader(err.StatusCode())
	w.Write(err.JSON())
}
