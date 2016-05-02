package goidc

import (
	"fmt"
	"net/http"

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
	realm           string
	handlers        map[string]grant.GrantHandlerFunc
	errorURIBuilder oer.OAuthErrorURIBuilder
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
		handlers: make(map[string]grant.GrantHandlerFunc),
	}
}

func (te *TokenEndpoint) Support(handler *grant.GrantHandler) {
	te.handlers[handler.Type] = handler.Func
}

func (te *TokenEndpoint) Handler(sdi sd.ServiceDataInterface) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		gt := r.FormValue("grant_type")
		if gt == "" {
			te.fail(w, oer.NewOAuthError(oer.ErrInvalidRequest, "missing 'grant_type' parameter"))
			return
		}
		h, exists := te.handlers[gt]
		if !exists {
			te.fail(w, oer.NewOAuthError(oer.ErrUnsupportedGrantType,
				fmt.Sprintf("unsupported 'grant_type' parameter: '%s'", gt)))
			return
		}
		cid, sec, inHeader, exists := te.findClientCredential(r)
		if !exists {
			te.failWithAuthHeader(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
			return
		}
		client, err := sdi.FindClientById(cid)
		if err != nil {
			if inHeader {
				te.failWithAuthHeader(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
			} else {
				te.fail(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
			}
			return
		}
		if client.Secret() != sec {
			if inHeader {
				te.failWithAuthHeader(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
			} else {
				te.fail(w, oer.NewOAuthSimpleError(oer.ErrInvalidClient))
			}
			return
		}
		if !client.CanUseGrantType(gt) {
			te.fail(w, oer.NewOAuthSimpleError(oer.ErrUnauthorizedClient))
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
