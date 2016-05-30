package goidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/lyokato/goidc/authorizer"
	"github.com/lyokato/goidc/bridge"
	"github.com/lyokato/goidc/flow"
	"github.com/lyokato/goidc/id_token"
	"github.com/lyokato/goidc/prompt"
	"github.com/lyokato/goidc/scope"
)

type AuthorizationEndpoint struct {
	sdi    bridge.ServiceDataInterface
	ai     bridge.AuthorizerInterface
	policy *authorizer.Policy
}

func NewAuthorizationEndpoint(sdi bridge.ServiceDataInterface,
	ai bridge.AuthorizerInterface, policy *authorizer.Policy) *AuthorizationEndpoint {
	return &AuthorizationEndpoint{
		sdi:    sdi,
		ai:     ai,
		policy: policy,
	}
}

func (a *AuthorizationEndpoint) HandleRequest(r *http.Request) bool {

	locales := r.FormValue("ui_locales")
	locale := a.ai.ChooseLocale(locales)

	cid := r.FormValue("client_id")
	if cid == "" {
		a.ai.RenderErrorPage(locale, authorizer.ErrMissingClientId)
		return false
	}

	ruri := r.FormValue("redirect_uri")
	if ruri == "" {
		a.ai.RenderErrorPage(locale, authorizer.ErrMissingRedirectURI)
		return false
	}

	clnt, serr := a.sdi.FindClientById(cid)
	if serr != nil {
		if serr.Type() == bridge.ErrFailed {
			a.ai.RenderErrorPage(locale, authorizer.ErrMissingClientId)
			return false
		} else if serr.Type() == bridge.ErrUnsupported {
			a.ai.RenderErrorPage(locale, authorizer.ErrServerError)
			return false
		} else if serr.Type() == bridge.ErrServerError {
			a.ai.RenderErrorPage(locale, authorizer.ErrServerError)
			return false
		}
	}

	if !clnt.CanUseRedirectURI(ruri) {
		a.ai.RenderErrorPage(locale, authorizer.ErrInvalidRedirectURI)
		return false
	}

	state := r.FormValue("state")

	rt := r.FormValue("response_type")
	if rt == "" {
		a.RedirectError(ruri, "invalid_request",
			"missing 'response_type'",
			state, "?")
		return false
	}

	f, err := flow.JudgeFromResponseType(rt)
	if err != nil {
		a.RedirectError(ruri, "invalid_request",
			fmt.Sprintf("invalid 'response_type:%s'", rt),
			state, "?")
		return false
	}

	if !clnt.CanUseFlow(f.Type) {
		a.RedirectErrorForFlow(ruri, "unauthorized_client", "", state, f)
		return false
	}

	display := authorizer.DisplayTypePage
	d := r.FormValue("display")
	if d != "" {
		if d == authorizer.DisplayTypePage ||
			d == authorizer.DisplayTypePopup ||
			d == authorizer.DisplayTypeWAP ||
			d == authorizer.DisplayTypeTouch {
			display = d
		} else {
			a.RedirectErrorForFlow(ruri, "invalid_request",
				fmt.Sprintf("unknown 'display': '%s'", d),
				state, f)
			return false
		}
	}

	var ma int
	mas := r.FormValue("max_age")
	if mas != "" {
		ma, err = strconv.Atoi(mas)
		if err != nil {
			a.RedirectErrorForFlow(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be integer", mas),
				state, f)
			return false
		}

		if ma < a.policy.MinMaxAge {
			a.RedirectErrorForFlow(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be greater than %d", a.policy.MinMaxAge-1),
				state, f)
			return false
		}

		if ma > a.policy.MaxMaxAge {
			a.RedirectErrorForFlow(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be less than %d", a.policy.MaxMaxAge+1),
				state, f)
			return false
		}
	}

	prmpt := ""
	p := r.FormValue("prompt")
	if p != "" {
		if prompt.Validate(p) {
			prmpt = p
		} else {
			a.RedirectErrorForFlow(ruri, "invalid_request",
				fmt.Sprintf("invalid 'prompt': '%s'", p),
				state, f)
			return false
		}
	}

	scp := r.FormValue("scope")

	if scope.IncludeOfflineAccess(scp) {
		if f.Type == flow.Implicit ||
			!prompt.IncludeConsent(prmpt) {
			scp = scope.RemoveOfflineAccess(scp)
		} else if !a.policy.AllowEmptyScope {
			scp_for_check := scope.RemoveOpenID(scp)
			scp_for_check = scope.RemoveOfflineAccess(scp_for_check)
			if len(scp_for_check) == 0 {
				a.RedirectErrorForFlow(ruri, "invalid_request",
					"when you request 'offline_access' scope, you should set scope other than 'openid'",
					state, f)
				return false
			}
		}
	}

	if scp == "" && !a.policy.AllowEmptyScope {
		a.RedirectErrorForFlow(ruri, "invalid_request",
			"missing 'scope'",
			state, f)
		return false
	}

	if f.RequireIdToken && !scope.IncludeOpenID(scp) {
		a.RedirectErrorForFlow(ruri, "invalid_request",
			fmt.Sprintf("'response_type:%s' requires id_token, but 'scope' doesn't include 'openid'", rt),
			state, f)
		return false
	}

	if !clnt.CanUseScope(f.Type, scp) {
		a.RedirectErrorForFlow(ruri, "invalid_scope", "", state, f)
		return false
	}

	n := r.FormValue("nonce")
	if f.Type != flow.AuthorizationCode &&
		scope.IncludeOpenID(scp) &&
		f.RequireIdToken &&
		n == "" {
		a.RedirectErrorForFlow(ruri, "invalid_request",
			fmt.Sprintf("'response_type:%s' requires 'nonce' parameter", rt),
			state, f)
		return false
	}

	if n != "" && len(n) > a.policy.MaxNonceLength {
		a.RedirectErrorForFlow(ruri, "invalid_request",
			fmt.Sprintf("length of 'nonce' should be less than %d",
				a.policy.MaxNonceLength+1),
			state, f)
		return false
	}

	verifier := r.FormValue("code_verifier")
	if verifier != "" && len(verifier) > a.policy.MaxCodeVerifierLength {
		a.RedirectErrorForFlow(ruri, "invalid_request",
			fmt.Sprintf("length of 'code_verifier' should be less than %d",
				a.policy.MaxCodeVerifierLength+1),
			state, f)
		return false
	}

	req := &authorizer.Request{
		Flow:         f,
		ClientId:     cid,
		RedirectURI:  ruri,
		Scope:        scp,
		State:        state,
		Nonce:        n,
		Display:      display,
		Prompt:       prmpt,
		MaxAge:       int64(ma),
		UILocales:    locales,
		CodeVerifier: verifier,
		IDTokenHint:  r.FormValue("id_token_hint"),
		LoginHint:    r.FormValue("login_hint"),
	}

	if req.Prompt == prompt.None {
		a.RedirectErrorForFlow(ruri, "interaction_required",
			"not allowed to use 'prompt:none'",
			state, f)
		return false
	} else {
		if !a.ai.ConfirmLoginSession(locale) {
			a.ai.RedirectToLogin(req)
			return false
		}
	}

	if prompt.IncludeLogin(req.Prompt) && a.ai.RequestIsFromLogin() {
		a.ai.RedirectToLogin(req)
		return false
	}

	authTime, serr := a.ai.GetAuthTime()
	if serr != nil {
		a.RedirectErrorForFlow(ruri, "server_error", "", state, f)
		return false
	}

	if req.MaxAge > 0 {
		age := time.Now().Unix() - authTime
		if req.MaxAge < age {
			a.ai.RedirectToLogin(req)
			return false
		}
	}

	if !prompt.IncludeConsent(req.Prompt) {
		policy := clnt.GetNoConsentPromptPolicy()
		switch policy {
		case prompt.NoConsentPromptPolicyOmitConsentIfCan:
			info, serr := a.sdi.FindAuthInfoByUserIdAndClientId(a.ai.GetLoginUserId(), req.ClientId)
			if serr != nil {
				if serr.Type() == bridge.ErrUnsupported {
					a.RedirectErrorForFlow(ruri, "server_error", "", state, f)
					return false
				} else if serr.Type() == bridge.ErrServerError {
					a.RedirectErrorForFlow(ruri, "server_error", "", state, f)
					return false
				}
			} else {
				if info != nil {
					a.RedirectErrorForFlow(ruri, "server_error", "", state, f)
					return false
				}
				if info.IsActive() && scope.Same(info.GetScope(), req.Scope) &&
					info.GetAuthorizedAt()+int64(a.policy.ConsentOmissionPeriod) > time.Now().Unix() {
					return a.complete(info, req)
				}
			}
		case prompt.NoConsentPromptPolicyForceConsent:
		}
	}
	a.ai.ShowConsentScreen(locale, display, req)
	return true
}

func (a *AuthorizationEndpoint) CompleteRequest(req *authorizer.Request) bool {
	info, serr := a.sdi.CreateOrUpdateAuthInfo(a.ai.GetLoginUserId(), req.ClientId, req.Scope)
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}
	return a.complete(info, req)
}

func (a *AuthorizationEndpoint) complete(
	info bridge.AuthInfoInterface, req *authorizer.Request) bool {
	switch req.Flow.Type {
	case flow.AuthorizationCode:
		return a.completeAuthorizationCodeFlowRequest(info, req)
	case flow.Implicit:
		return a.completeImplicitFlowRequest(info, req)
	case flow.Hybrid:
		return a.completeHybridFlowRequest(info, req)
	}
	return false
}

func (a *AuthorizationEndpoint) completeAuthorizationCodeFlowRequest(
	info bridge.AuthInfoInterface, req *authorizer.Request) bool {
	code, serr := a.ai.CreateUniqueCode()
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "?")
		return false
	}
	authTime, serr := a.ai.GetAuthTime()
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "?")
		return false
	}
	serr = a.sdi.CreateAuthSession(info,
		req.ToSession(code, int64(a.policy.AuthSessionExpiresIn), authTime))
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "?")
		return false
	}
	params := url.Values{}
	params.Add("code", code)
	if req.State != "" {
		params.Add("state", req.State)
	}
	u := fmt.Sprintf("%s?%s", req.RedirectURI, params.Encode())
	a.ai.Redirect(u)
	return true
}

func (a *AuthorizationEndpoint) completeImplicitFlowRequest(
	info bridge.AuthInfoInterface, req *authorizer.Request) bool {

	clnt, serr := a.sdi.FindClientById(req.ClientId)
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}

	params := url.Values{}
	if req.State != "" {
		params.Add("state", req.State)
	}
	at := ""
	if req.Flow.RequireAccessToken {
		t, serr := a.sdi.CreateOAuthToken(info, false)
		if serr != nil {
			a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
			return false
		}
		at = t.GetAccessToken()
		params.Add("access_token", at)
		params.Add("token_type", "bearer")
		params.Add("expires_in",
			fmt.Sprintf("%d", t.GetAccessTokenExpiresIn()))
	}

	authTime, serr := a.ai.GetAuthTime()
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}

	if req.Flow.RequireIdToken {
		idt, err := id_token.GenForImplicit(
			clnt.GetIdTokenAlg(),             // id_token signing algorithm
			clnt.GetIdTokenKey(),             // id_token signing key
			clnt.GetIdTokenKeyId(),           // id_token signing key-id
			a.sdi.Issuer(),                   // issuer
			info.GetClientId(),               // clientId
			info.GetSubject(),                // subject
			req.Nonce,                        // nonce
			int64(a.policy.IdTokenExpiresIn), // expiresIn,
			authTime, // authTime
			at,       // access token
		)
		if err != nil {
			a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
			return false
		}
		params.Add("id_token", idt)
	}
	u := fmt.Sprintf("%s#%s", req.RedirectURI, params.Encode())
	a.ai.Redirect(u)
	return true
}

func (a *AuthorizationEndpoint) completeHybridFlowRequest(
	info bridge.AuthInfoInterface, req *authorizer.Request) bool {

	code, serr := a.ai.CreateUniqueCode()

	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}

	authTime, serr := a.ai.GetAuthTime()
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}

	serr = a.sdi.CreateAuthSession(info,
		req.ToSession(code, int64(a.policy.AuthSessionExpiresIn), authTime))
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}

	clnt, serr := a.sdi.FindClientById(req.ClientId)
	if serr != nil {
		a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
		return false
	}

	params := url.Values{}
	params.Add("code", code)
	if req.State != "" {
		params.Add("state", req.State)
	}

	at := ""
	if req.Flow.RequireAccessToken {
		t, serr := a.sdi.CreateOAuthToken(info, false)
		if serr != nil {
			a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
			return false
		}
		at = t.GetAccessToken()
		params.Add("access_token", at)
		params.Add("token_type", "bearer")
		params.Add("expires_in",
			fmt.Sprintf("%d", t.GetAccessTokenExpiresIn()))
	}

	if req.Flow.RequireIdToken {
		idt, err := id_token.GenForHybrid(
			clnt.GetIdTokenAlg(),             // id_token signing algorithm
			clnt.GetIdTokenKey(),             // id_token signing key
			clnt.GetIdTokenKeyId(),           // id_token signing key-id
			a.sdi.Issuer(),                   // issuer
			info.GetClientId(),               // clientId
			info.GetSubject(),                // subject
			req.Nonce,                        // nonce
			int64(a.policy.IdTokenExpiresIn), // expiresIn,
			authTime, // authTime
			at,       // access_token
			code,     // code
		)
		if err != nil {
			a.RedirectError(req.RedirectURI, "server_error", "", req.State, "#")
			return false
		}
		params.Add("id_token", idt)
	}
	u := fmt.Sprintf("%s#%s", req.RedirectURI, params.Encode())
	a.ai.Redirect(u)
	return true
}

func (a *AuthorizationEndpoint) RedirectErrorForFlow(uri, typ, desc, state string, flw *flow.Flow) {
	connector := "?"
	if flw.Type != flow.AuthorizationCode {
		connector = "#"
	}
	a.RedirectError(uri, typ, desc, state, connector)
}

func (a *AuthorizationEndpoint) RedirectError(uri, typ, desc, state, connector string) {
	params := url.Values{}
	params.Add("error", typ)
	if desc != "" {
		params.Add("error_description", desc)
	}
	if state != "" {
		params.Add("state", state)
	}
	u := fmt.Sprintf("%s%s%s", uri, connector, params.Encode())
	a.ai.Redirect(u)
}
