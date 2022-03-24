package authorization

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
)

type ResponseParamType int

const (
	ParamTypeQuery ResponseParamType = iota
	ParamTypeFragment
)

type (
	ResponseHandler interface {
		Success(uri string, params map[string]string)
		Error(uri, typ, desc, state string)
	}

	RedirectResponseHandler struct {
		w  http.ResponseWriter
		r  *http.Request
		pt ResponseParamType
	}

	HTMLResponseHandler struct {
		w http.ResponseWriter
		r *http.Request
	}
)

func (t ResponseParamType) Connector(uri string) string {
	u, _ := url.Parse(uri)
	switch t {
	case ParamTypeQuery:
		if len(u.RawQuery) == 0 {
			return "?"
		} else {
			return "&"
		}
	case ParamTypeFragment:
		if len(u.Fragment) == 0 {
			return "#"
		} else {
			return "&"
		}
	default:
		if len(u.RawQuery) == 0 {
			return "?"
		} else {
			return "&"
		}
	}
}

func ResponseHandlerForMode(mode string, w http.ResponseWriter, r *http.Request) ResponseHandler {
	switch mode {
	case "query":
		return NewRedirectResponseHandler(w, r, ParamTypeQuery)
	case "fragment":
		return NewRedirectResponseHandler(w, r, ParamTypeFragment)
	case "form_post":
		return NewHTMLResponseHandler(w, r)
	default:
		return NewRedirectResponseHandler(w, r, ParamTypeQuery)
	}
}

func NewRedirectResponseHandler(w http.ResponseWriter, r *http.Request, pt ResponseParamType) *RedirectResponseHandler {
	return &RedirectResponseHandler{
		w:  w,
		r:  r,
		pt: pt,
	}
}

func (h *RedirectResponseHandler) Success(uri string, params map[string]string) {
	values := url.Values{}
	for k, v := range params {
		values.Add(k, v)
	}
	u := fmt.Sprintf("%s%s%s", uri, h.pt.Connector(uri), values.Encode())
	http.Redirect(h.w, h.r, u, http.StatusFound)
}

func (h *RedirectResponseHandler) Error(uri, typ, desc, state string) {
	params := url.Values{}
	params.Add("error", typ)
	if desc != "" {
		params.Add("error_description", desc)
	}
	if state != "" {
		params.Add("state", state)
	}
	u := fmt.Sprintf("%s%s%s", uri, h.pt.Connector(uri), params.Encode())
	http.Redirect(h.w, h.r, u, http.StatusFound)
}

func NewHTMLResponseHandler(w http.ResponseWriter, r *http.Request) *HTMLResponseHandler {
	return &HTMLResponseHandler{
		w: w,
		r: r,
	}
}

func (h *HTMLResponseHandler) Success(uri string, params map[string]string) {
	h.render(uri, params)
}

func (h *HTMLResponseHandler) Error(uri, typ, desc, state string) {
	params := make(map[string]string)
	params["error"] = typ
	if desc != "" {
		params["error_description"] = desc
	}
	if state != "" {
		params["state"] = state
	}
	h.render(uri, params)
}

func (h *HTMLResponseHandler) render(uri string, params map[string]string) {
	doc := `<html><head><title>Submit This Form</title></head><body onload="javascript:document.forms[0].submit()">`
	doc = doc + fmt.Sprintf(`<form method="post" action="%s">`, uri)
	for k, v := range params {
		doc = doc + fmt.Sprintf(`<input type="hidden" name="%s" value="%s" />`, k, html.EscapeString(v))
	}
	doc = doc + `</form></body></html>`
	h.w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	h.w.Header().Set("Cache-Control", "no-cache, no-store")
	h.w.Header().Set("Pragma", "no-cache")
	h.w.WriteHeader(http.StatusOK)
	h.w.Write([]byte(doc))
}
