package authorizer

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/lyokato/goidc/scope"
)

func ConvertHTTPRequest(r *http.Request) (*Request, error) {

	rt := r.FormValue("response_type")
	if rt == "" {
		return nil, errors.New("missing 'response_type' parameter")
	}

	f, err := JudgeFlowFromResponseType(rt)
	if err != nil {
		return nil, err
	}

	cid := r.FormValue("client_id")
	if cid == "" {
		return nil, errors.New("missing 'client_id' parameter")
	}
	ruri := r.FormValue("redirect_uri")
	if ruri == "" {
		return nil, errors.New("missing 'redirect_uri' parameter")
	}

	ma := 0
	mas := r.FormValue("max_age")
	if mas != "" {
		ma, err = strconv.Atoi(mas)
		if err != nil {
			return nil, fmt.Errorf("'max_age' should be integer: %s", mas)
		}
	}

	display := DisplayTypePage
	d := r.FormValue("display")
	if d != "" {
		if d == DisplayTypePage || d == DisplayTypePopup ||
			d == DisplayTypeWAP || d == DisplayTypeTouch {
			display = d
		} else {
			return nil, fmt.Errorf("Unknown value for 'display': %s", d)
		}
	}

	prompt := PromptTypeDefault
	p := r.FormValue("prompt")
	if p != "" {
		if p == PromptTypeNone || d == PromptTypeLogin ||
			p == PromptTypeConsent || p == PromptTypeSelectAccount {
			prompt = p
		} else {
			return nil, fmt.Errorf("Unknown value for 'prompt': %s", p)
		}
	}

	s := r.FormValue("scope")
	if s == "" {
		return nil, errors.New("missing 'scope' parameter")
	}

	if f.Type == FlowTypeBasic {
		if !scope.IncludeOfflineAccess(s) {
			s = s + " offline_access"
		}
	} else {
		if scope.IncludeOfflineAccess(s) {
			return nil, errors.New("'offline_access' is not supported on implicit/hybrid flow")
		}
	}

	n := r.FormValue("nonce")
	if f.Type != FlowTypeBasic {
		if scope.IncludeOpenID(s) && n == "" {
			return nil, errors.New("'nonce' parameter is required on implicit/hybrid flow if it's for OpenID")
		}
	}

	return &Request{
		Flow:         f,
		ClientId:     cid,
		RedirectURI:  ruri,
		Scope:        s,
		State:        r.FormValue("state"),
		CodeVerifier: r.FormValue("code_verifier"),
		Nonce:        n,
		Display:      display,
		Prompt:       prompt,
		MaxAge:       ma,
		UILocales:    r.FormValue("ui_locales"),
		IDTokenHint:  r.FormValue("id_token_hint"),
		LoginHint:    r.FormValue("login_hint"),
	}, nil
}
