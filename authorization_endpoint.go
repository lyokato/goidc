package goidc

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lyokato/goidc/authorization"
	"github.com/lyokato/goidc/bridge"
	"github.com/lyokato/goidc/flow"
	"github.com/lyokato/goidc/id_token"
	"github.com/lyokato/goidc/prompt"
	"github.com/lyokato/goidc/response_mode"
	"github.com/lyokato/goidc/scope"
)

type AuthorizationEndpoint struct {
	sdi    bridge.DataInterface
	policy *authorization.Policy
}

func NewAuthorizationEndpoint(sdi bridge.DataInterface, policy *authorization.Policy) *AuthorizationEndpoint {
	return &AuthorizationEndpoint{
		sdi:    sdi,
		policy: policy,
	}
}

func (a *AuthorizationEndpoint) HandleRequest(w http.ResponseWriter,
	r *http.Request, callbacks bridge.AuthorizationCallbacks) bool {

	cid := r.FormValue("client_id")
	if cid == "" {
		callbacks.RenderErrorPage(authorization.ErrMissingClientId)
		return false
	}

	ruri := r.FormValue("redirect_uri")
	if ruri == "" {
		callbacks.RenderErrorPage(authorization.ErrMissingRedirectURI)
		return false
	}

	clnt, serr := a.sdi.FindClientById(cid)
	if serr != nil {
		if serr.Type() == bridge.ErrFailed {
			callbacks.RenderErrorPage(authorization.ErrMissingClientId)
			return false
		} else if serr.Type() == bridge.ErrUnsupported {
			callbacks.RenderErrorPage(authorization.ErrServerError)
			return false
		} else if serr.Type() == bridge.ErrServerError {
			callbacks.RenderErrorPage(authorization.ErrServerError)
			return false
		}
	}

	if !clnt.CanUseRedirectURI(ruri) {
		callbacks.RenderErrorPage(authorization.ErrInvalidRedirectURI)
		return false
	}

	state := r.FormValue("state")
	rmode := r.FormValue("response_mode")

	rt := r.FormValue("response_type")
	if rt == "" {
		authorization.ResponseHandlerForMode(rmode, w, r).Error(
			ruri, "invalid_request", "missing 'response_type'", state)
		return false
	}

	f, err := flow.JudgeByResponseType(rt)
	if err != nil {
		authorization.ResponseHandlerForMode(rmode, w, r).Error(
			ruri, "invalid_request",
			fmt.Sprintf("invalid 'response_type:%s'", rt),
			state)
		return false
	}

	var defaultRM string
	switch f.Type {
	case flow.AuthorizationCode:
		defaultRM = a.policy.DefaultAuthorizationCodeFlowResponseMode
	case flow.Implicit:
		defaultRM = a.policy.DefaultImplicitFlowResponseMode
	case flow.Hybrid:
		defaultRM = a.policy.DefaultImplicitFlowResponseMode
	default:
		defaultRM = a.policy.DefaultAuthorizationCodeFlowResponseMode
	}

	if rmode == "" {
		rmode = defaultRM
	} else {
		if !response_mode.Validate(rmode) {
			if a.policy.IgnoreInvalidResponseMode {
				rmode = defaultRM
			} else {
				authorization.ResponseHandlerForMode(defaultRM, w, r).Error(
					ruri, "invalid_request",
					fmt.Sprintf("unknown 'response_mode': '%s'", rmode),
					state)
			}
		}
	}

	if a.policy.RequireResponseModeSecurityLevelCheck {
		if !response_mode.CompareSecurityLevel(rmode, defaultRM) {
			if a.policy.IgnoreInvalidResponseMode {
				rmode = defaultRM
			} else {
				authorization.ResponseHandlerForMode(defaultRM, w, r).Error(
					ruri, "invalid_request",
					fmt.Sprintf("'response_mode:%s' isn't allowed for 'response_type:%s'", rmode, rt),
					state)
			}
		}
	}

	rh := authorization.ResponseHandlerForMode(rmode, w, r)

	if !clnt.CanUseFlow(f.Type) {
		rh.Error(ruri, "unauthorized_client", "", state)
		return false
	}

	display := authorization.DisplayTypePage
	d := r.FormValue("display")
	if d != "" {
		if d == authorization.DisplayTypePage ||
			d == authorization.DisplayTypePopup ||
			d == authorization.DisplayTypeWAP ||
			d == authorization.DisplayTypeTouch {
			display = d
		} else {
			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("unknown 'display': '%s'", d),
				state)
			return false
		}
	}

	var ma int
	mas := r.FormValue("max_age")
	if mas != "" {
		ma, err = strconv.Atoi(mas)
		if err != nil {
			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be integer", mas),
				state)
			return false
		}

		if ma < a.policy.MinMaxAge {
			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be greater than %d", a.policy.MinMaxAge-1),
				state)
			return false
		}

		if ma > a.policy.MaxMaxAge {
			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be less than %d", a.policy.MaxMaxAge+1),
				state)
			return false
		}
	}

	prmpt := ""
	p := r.FormValue("prompt")
	if p != "" {
		if prompt.Validate(p) {
			prmpt = p
		} else {
			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("invalid 'prompt': '%s'", p),
				state)
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
				rh.Error(ruri, "invalid_request",
					"when you request 'offline_access' scope, you should set scope other than 'openid'",
					state)
				return false
			}
		}
	}

	if scp == "" && !a.policy.AllowEmptyScope {
		rh.Error(ruri, "invalid_request",
			"missing 'scope'",
			state)
		return false
	}

	if f.RequireIdToken && !scope.IncludeOpenID(scp) {
		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("'response_type:%s' requires id_token, but 'scope' doesn't include 'openid'", rt),
			state)
		return false
	}

	if !clnt.CanUseScope(f.Type, scp) {
		rh.Error(ruri, "invalid_scope", "", state)
		return false
	}

	n := r.FormValue("nonce")
	if f.Type != flow.AuthorizationCode &&
		scope.IncludeOpenID(scp) &&
		f.RequireIdToken &&
		n == "" {
		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("'response_type:%s' requires 'nonce' parameter", rt),
			state)
		return false
	}

	if n != "" && len(n) > a.policy.MaxNonceLength {
		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("length of 'nonce' should be less than %d",
				a.policy.MaxNonceLength+1),
			state)
		return false
	}

	verifier := r.FormValue("code_verifier")
	if verifier != "" && len(verifier) > a.policy.MaxCodeVerifierLength {
		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("length of 'code_verifier' should be less than %d",
				a.policy.MaxCodeVerifierLength+1),
			state)
		return false
	}

	locales := r.FormValue("ui_locales")
	locale, err := callbacks.ChooseLocale(locales)
	if err != nil {
		rh.Error(ruri, "server_error", "", state)
		return false
	}

	req := &authorization.Request{
		Flow:         f,
		ClientId:     cid,
		RedirectURI:  ruri,
		Scope:        scp,
		ResponseMode: rmode,
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
		rh.Error(ruri, "interaction_required",
			"not allowed to use 'prompt:none'",
			state)
		return false
	} else {
		isLoginSession, err := callbacks.ConfirmLoginSession()
		if err != nil {
			rh.Error(ruri, "server_error", "", state)
			return false
		}
		if !isLoginSession {
			err = callbacks.RedirectToLogin(req)
			if err != nil {
				rh.Error(ruri, "server_error", "", state)
				return false
			}
			return false
		}
	}

	if prompt.IncludeLogin(req.Prompt) {
		isFromLogin, err := callbacks.RequestIsFromLogin()
		if err != nil {
			rh.Error(ruri, "server_error", "", state)
			return false
		}
		if !isFromLogin {
			callbacks.RedirectToLogin(req)
			return false
		}
	}

	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		rh.Error(ruri, "server_error", "", state)
		return false
	}

	if req.MaxAge > 0 {
		age := time.Now().Unix() - authTime
		if req.MaxAge < age {
			callbacks.RedirectToLogin(req)
			return false
		}
	}

	if !prompt.IncludeConsent(req.Prompt) {
		policy := clnt.GetNoConsentPromptPolicy()
		switch policy {
		case prompt.NoConsentPromptPolicyOmitConsentIfCan:
			uid, err := callbacks.GetLoginUserId()
			if err != nil {
				rh.Error(ruri, "server_error", "", state)
				return false
			}
			info, serr := a.sdi.FindAuthInfoByUserIdAndClientId(uid, req.ClientId)
			if serr != nil {
				if serr.Type() == bridge.ErrUnsupported {
					rh.Error(ruri, "server_error", "", state)
					return false
				} else if serr.Type() == bridge.ErrServerError {
					rh.Error(ruri, "server_error", "", state)
					return false
				}
			} else {
				if info == nil {
					rh.Error(ruri, "server_error", "", state)
					return false
				}
				if info.IsActive() && scope.Same(info.GetScope(), req.Scope) &&
					info.GetAuthorizedAt()+int64(a.policy.ConsentOmissionPeriod) > time.Now().Unix() {
					return a.complete(callbacks, rh, info, req)
				}
			}
		case prompt.NoConsentPromptPolicyForceConsent:
		}
	}
	err = callbacks.ShowConsentScreen(locale, display, clnt, req)
	if err != nil {
		rh.Error(ruri, "server_error", "", state)
		return false
	}
	return true
}

func (a *AuthorizationEndpoint) CompleteRequest(w http.ResponseWriter, r *http.Request,
	req *authorization.Request, callbacks bridge.AuthorizationCallbacks) bool {
	rh := authorization.ResponseHandlerForMode(req.ResponseMode, w, r)
	uid, err := callbacks.GetLoginUserId()
	if err != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	info, serr := a.sdi.CreateOrUpdateAuthInfo(uid, req.ClientId, req.Scope)
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	return a.complete(callbacks, rh, info, req)
}

func (a *AuthorizationEndpoint) complete(
	callbacks bridge.AuthorizationCallbacks,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo, req *authorization.Request) bool {
	switch req.Flow.Type {
	case flow.AuthorizationCode:
		return a.completeAuthorizationCodeFlowRequest(callbacks, rh, info, req)
	case flow.Implicit:
		return a.completeImplicitFlowRequest(callbacks, rh, info, req)
	case flow.Hybrid:
		return a.completeHybridFlowRequest(callbacks, rh, info, req)
	}
	return false
}

func (a *AuthorizationEndpoint) completeAuthorizationCodeFlowRequest(
	callbacks bridge.AuthorizationCallbacks,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo,
	req *authorization.Request) bool {
	code, err := callbacks.CreateAuthorizationCode()
	if err != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	serr := a.sdi.CreateAuthSession(info,
		req.ToSession(code, int64(a.policy.AuthSessionExpiresIn), authTime))
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	params := make(map[string]string)
	params["code"] = code
	if req.State != "" {
		params["state"] = req.State
	}
	rh.Success(req.RedirectURI, params)
	return true
}

func (a *AuthorizationEndpoint) completeImplicitFlowRequest(
	callbacks bridge.AuthorizationCallbacks,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo,
	req *authorization.Request) bool {

	clnt, serr := a.sdi.FindClientById(req.ClientId)
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	params := make(map[string]string)
	if req.State != "" {
		params["state"] = req.State
	}
	if req.Scope != "" {
		params["scope"] = req.Scope
	}
	at := ""
	if req.Flow.RequireAccessToken {
		t, serr := a.sdi.CreateOAuthToken(info, false)
		if serr != nil {
			rh.Error(req.RedirectURI, "server_error", "", req.State)
			return false
		}
		at = t.GetAccessToken()
		params["access_token"] = at
		params["token_type"] = "bearer"
		params["rexpires_in"] = fmt.Sprintf("%d", t.GetAccessTokenExpiresIn())
	}

	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
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
			rh.Error(req.RedirectURI, "server_error", "", req.State)
			return false
		}
		params["id_token"] = idt
	}
	rh.Success(req.RedirectURI, params)
	return true
}

func (a *AuthorizationEndpoint) completeHybridFlowRequest(
	callbacks bridge.AuthorizationCallbacks,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo,
	req *authorization.Request) bool {

	code, err := callbacks.CreateAuthorizationCode()

	if err != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	serr := a.sdi.CreateAuthSession(info,
		req.ToSession(code, int64(a.policy.AuthSessionExpiresIn), authTime))
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	clnt, serr := a.sdi.FindClientById(req.ClientId)
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	params := make(map[string]string)
	params["code"] = code
	if req.State != "" {
		params["state"] = req.State
	}
	if req.Scope != "" {
		params["scope"] = req.Scope
	}

	at := ""
	if req.Flow.RequireAccessToken {
		t, serr := a.sdi.CreateOAuthToken(info, false)
		if serr != nil {
			rh.Error(req.RedirectURI, "server_error", "", req.State)
			return false
		}
		at = t.GetAccessToken()
		params["access_token"] = at
		params["token_type"] = "bearer"
		params["expires_in"] = fmt.Sprintf("%d", t.GetAccessTokenExpiresIn())
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
			rh.Error(req.RedirectURI, "server_error", "", req.State)
			return false
		}
		params["id_token"] = idt
	}
	rh.Success(req.RedirectURI, params)
	return true
}
