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
	"github.com/lyokato/goidc/log"
	"github.com/lyokato/goidc/prompt"
	"github.com/lyokato/goidc/response_mode"
	"github.com/lyokato/goidc/scope"
)

type AuthorizationEndpoint struct {
	di     bridge.DataInterface
	policy *authorization.Policy
	logger log.Logger
}

func NewAuthorizationEndpoint(di bridge.DataInterface, policy *authorization.Policy) *AuthorizationEndpoint {
	return &AuthorizationEndpoint{
		di:     di,
		policy: policy,
		logger: log.NewDefaultLogger(),
	}
}

func (a *AuthorizationEndpoint) SetLogger(l log.Logger) {
	a.logger = l
}

func (a *AuthorizationEndpoint) HandleRequest(w http.ResponseWriter,
	r *http.Request, callbacks bridge.AuthorizationCallbacks) bool {

	cid := r.FormValue("client_id")
	if cid == "" {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.MissingParam,
			map[string]string{
				"param": "client_id",
			},
			"'client_id' not found in request."))

		callbacks.ShowErrorScreen(authorization.ErrMissingClientId)
		return false
	}

	ruri := r.FormValue("redirect_uri")
	if ruri == "" {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.MissingParam,
			map[string]string{
				"param": "redirect_uri",
			},
			"'redirect_uri' not found in request."))

		callbacks.ShowErrorScreen(authorization.ErrMissingRedirectURI)
		return false
	}

	clnt, serr := a.di.FindClientById(cid)
	if serr != nil {
		if serr.Type() == bridge.ErrFailed {

			a.logger.Info(log.AuthorizationEndpointLog(r.URL.Path,
				log.NoEnabledClient,
				map[string]string{
					"method":    "FindClientById",
					"client_id": cid,
				},
				"client associated with the client_id not found"))

			callbacks.ShowErrorScreen(authorization.ErrMissingClientId)
			return false

		} else if serr.Type() == bridge.ErrUnsupported {

			a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
				log.InterfaceUnsupported,
				map[string]string{
					"method": "FindClientById",
				},
				"this method returns 'unsupported' error"))

			callbacks.ShowErrorScreen(authorization.ErrServerError)
			return false

		} else if serr.Type() == bridge.ErrServerError {

			a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
				log.InterfaceError,
				map[string]string{
					"method":    "FindClientById",
					"client_id": cid,
				},
				"this method returns ServerError"))

			callbacks.ShowErrorScreen(authorization.ErrServerError)
			return false
		}
	} else {
		if clnt == nil {
			a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
				log.InterfaceError,
				map[string]string{
					"method":    "FindClientById",
					"client_id": cid,
				},
				"this method returns (nil, nil)."))

			callbacks.ShowErrorScreen(authorization.ErrServerError)
			return false
		}
	}

	if !clnt.CanUseRedirectURI(ruri) {

		a.logger.Info(log.AuthorizationEndpointLog(r.URL.Path,
			log.RedirectURIMismatch,
			map[string]string{
				"method":       "CanUseRedirectURI",
				"client_id":    cid,
				"redirect_uri": ruri,
			},
			"this 'redirect_uri' is not allowed for this client."))

		callbacks.ShowErrorScreen(authorization.ErrInvalidRedirectURI)
		return false
	}

	state := r.FormValue("state")
	rmode := r.FormValue("response_mode")

	rt := r.FormValue("response_type")
	if rt == "" {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.MissingParam,
			map[string]string{
				"param": "response_type",
			},
			"'redirect_uri' not found in request."))

		authorization.ResponseHandlerForMode(rmode, w, r).Error(
			ruri, "invalid_request", "missing 'response_type'", state)
		return false
	}

	f, err := flow.JudgeByResponseType(rt)
	if err != nil {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidResponseType,
			map[string]string{
				"response_type": rt,
			},
			"'response_type' is not appropriate."))

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

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.MissingParam,
			map[string]string{
				"param":   "response_mode",
				"default": defaultRM,
			},
			"'response_mode' not found so, set default for this flow."))

		rmode = defaultRM
	} else {
		if !response_mode.Validate(rmode) {

			if a.policy.IgnoreInvalidResponseMode {

				a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
					log.InvalidResponseMode,
					map[string]string{
						"response_mode": rmode,
						"default":       defaultRM,
					},
					"this 'response_mode' is invalid, so set default"))

				rmode = defaultRM

			} else {

				a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
					log.InvalidResponseMode,
					map[string]string{
						"response_mode": rmode,
					},
					"this 'response_mode' is invalid, so return error"))

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

				a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
					log.InvalidResponseMode,
					map[string]string{
						"response_mode": rmode,
						"default":       defaultRM,
					},
					"this 'response_mode' is not secure than default, so set default."))
				rmode = defaultRM

			} else {

				a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
					log.InvalidResponseMode,
					map[string]string{
						"response_mode": rmode,
					},
					"this 'response_mode' is not secure than default, so return error."))
				authorization.ResponseHandlerForMode(defaultRM, w, r).Error(
					ruri, "invalid_request",
					fmt.Sprintf("'response_mode:%s' isn't allowed for 'response_type:%s'", rmode, rt),
					state)
			}
		}
	}

	rh := authorization.ResponseHandlerForMode(rmode, w, r)

	if !clnt.CanUseFlow(f.Type) {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidResponseType,
			map[string]string{
				"response_type": rt,
				"flow_type":     f.Type.String(),
			},
			"this flow is not allowed for this client."))

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

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.InvalidDisplay,
				map[string]string{
					"display": d,
				},
				"invalid 'display' parameter."))

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

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.InvalidMaxAge,
				map[string]string{},
				"'max_age' is not an integer value."))

			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be integer", mas),
				state)
			return false
		}

		if ma < a.policy.MinMaxAge {

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.InvalidMaxAge,
				map[string]string{
					"max_age": mas,
				},
				"'max_age' is less than minimum."))

			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("'max_age' should be greater than %d", a.policy.MinMaxAge-1),
				state)
			return false
		}

		if ma > a.policy.MaxMaxAge {

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.InvalidMaxAge,
				map[string]string{
					"max_age": mas,
				},
				"'max_age' is greater than maximum."))

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

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.InvalidPrompt,
				map[string]string{
					"prompt": p,
				},
				"unknown 'prompt' is set."))

			rh.Error(ruri, "invalid_request",
				fmt.Sprintf("invalid 'prompt': '%s'", p),
				state)
			return false
		}
	} else {
		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.MissingParam,
			map[string]string{
				"param": "prompt",
			},
			"'prompt' not found."))

	}

	scp := r.FormValue("scope")

	if scope.IncludeOfflineAccess(scp) {

		if f.Type == flow.Implicit ||

			!prompt.IncludeConsent(prmpt) {

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.InvalidScope,
				map[string]string{
					"scope": "offline_access",
				},
				"'offline_access' shouldn't be set with implicit-flow or without-consent. ignore."))

			scp = scope.RemoveOfflineAccess(scp)

		} else if !a.policy.AllowEmptyScope {

			scp_for_check := scope.RemoveOpenID(scp)
			scp_for_check = scope.RemoveOfflineAccess(scp_for_check)

			if len(scp_for_check) == 0 {

				a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
					log.InvalidScope,
					map[string]string{
						"scope": "offline_access",
					},
					"'offline_access' shouldt be set with other scope other than openid."))

				rh.Error(ruri, "invalid_request",
					"when you request 'offline_access' scope, you should set scope other than 'openid'",
					state)
				return false
			}
		}
	}

	if scp == "" && !a.policy.AllowEmptyScope {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidScope,
			map[string]string{},
			"'scope' shouldn't be empty"))

		rh.Error(ruri, "invalid_request",
			"missing 'scope'",
			state)
		return false
	}

	if f.RequireIdToken && !scope.IncludeOpenID(scp) {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidScope,
			map[string]string{
				"response_type": rt,
				"scope":         scp,
			},
			"'scope' should include 'openid' for this 'response_type'."))

		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("'response_type:%s' requires id_token, but 'scope' doesn't include 'openid'", rt),
			state)
		return false
	}

	if !clnt.CanUseScope(f.Type, scp) {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidScope,
			map[string]string{
				"scope":     scp,
				"client_id": cid,
			},
			"this 'scope' is not allowed for this client"))

		rh.Error(ruri, "invalid_scope", "", state)
		return false
	}

	n := r.FormValue("nonce")
	if f.Type != flow.AuthorizationCode &&
		scope.IncludeOpenID(scp) &&
		f.RequireIdToken &&
		n == "" {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.MissingParam,
			map[string]string{
				"param":         "nonce",
				"response_type": rt,
			},
			"'nonce' is required for this 'response_type'."))

		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("'response_type:%s' requires 'nonce' parameter", rt),
			state)
		return false
	}

	if n != "" && len(n) > a.policy.MaxNonceLength {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidNonce,
			map[string]string{
				"nonce": n,
			},
			"length of 'nonce' is too long."))

		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("length of 'nonce' should be less than %d",
				a.policy.MaxNonceLength+1),
			state)
		return false
	}

	verifier := r.FormValue("code_verifier")
	if verifier != "" && len(verifier) > a.policy.MaxCodeVerifierLength {

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidCodeVerifier,
			map[string]string{
				"code_verifier": verifier,
			},
			"length of 'code_verifier' is too long."))

		rh.Error(ruri, "invalid_request",
			fmt.Sprintf("length of 'code_verifier' should be less than %d",
				a.policy.MaxCodeVerifierLength+1),
			state)
		return false
	}

	locales := r.FormValue("ui_locales")
	locale, err := callbacks.ChooseLocale(locales)
	if err != nil {

		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "ChooseLocale",
			},
			err.Error()))

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

		a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
			log.InvalidPrompt,
			map[string]string{
				"prompt": "none",
			},
			"this 'prompt' not supported"))

		rh.Error(ruri, "interaction_required",
			"not allowed to use 'prompt:none'",
			state)
		return false

	} else {

		isLoginSession, err := callbacks.ConfirmLoginSession()

		if err != nil {

			a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
				log.InterfaceError,
				map[string]string{
					"method": "ConfirmLoginSession",
				},
				err.Error()))

			rh.Error(ruri, "server_error", "", state)
			return false
		}

		if !isLoginSession {

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.LoginRequired,
				map[string]string{},
				"this is non-signed-in-session, so, show login page."))

			err = callbacks.ShowLoginScreen(locale, display, req)
			if err != nil {

				a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
					log.InterfaceError,
					map[string]string{
						"method": "ShowLoginScreen",
					},
					err.Error()))

				rh.Error(ruri, "server_error", "", state)
				return false
			}
			return false
		}
	}

	if prompt.IncludeLogin(req.Prompt) {

		isFromLogin, err := callbacks.RequestIsFromLogin()

		if err != nil {

			a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
				log.InterfaceError,
				map[string]string{
					"method": "RequestIsFromLogin",
				},
				err.Error()))

			rh.Error(ruri, "server_error", "", state)
			return false
		}

		if !isFromLogin {

			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.LoginRequired,
				map[string]string{
					"prompt": req.Prompt,
				},
				"force-login is required by 'prompt'"))

			callbacks.ShowLoginScreen(locale, display, req)
			return false
		}
	}

	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "GetAuthTime",
			},
			err.Error()))
		rh.Error(ruri, "server_error", "", state)
		return false
	}

	if req.MaxAge > 0 {
		age := time.Now().Unix() - authTime
		if req.MaxAge < age {
			a.logger.Debug(log.AuthorizationEndpointLog(r.URL.Path,
				log.LoginRequired,
				map[string]string{
					"max_age": mas,
				},
				"'auth_time' is over 'max_age', so, show login page."))
			callbacks.ShowLoginScreen(locale, display, req)
			return false
		}
	}

	if !prompt.IncludeConsent(req.Prompt) {
		policy := clnt.GetNoConsentPromptPolicy()
		switch policy {
		case prompt.NoConsentPromptPolicyOmitConsentIfCan:
			uid, err := callbacks.GetLoginUserId()
			if err != nil {
				a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
					log.InterfaceError,
					map[string]string{
						"method": "GetLoginUserId",
					},
					err.Error()))
				rh.Error(ruri, "server_error", "", state)
				return false
			}
			info, serr := a.di.FindAuthInfoByUserIdAndClientId(uid, req.ClientId)
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
					return a.complete(callbacks, r, rh, info, req)
				}
			}
		case prompt.NoConsentPromptPolicyForceConsent:
		}
	}
	err = callbacks.ShowConsentScreen(locale, display, clnt, req)
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "ShowConsentScreen",
			},
			err.Error()))
		rh.Error(ruri, "server_error", "", state)
		return false
	}
	return true
}

func (a *AuthorizationEndpoint) CancelRequest(w http.ResponseWriter, r *http.Request,
	callbacks bridge.AuthorizationCallbacks) bool {
	req, err := callbacks.Continue()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "Continue",
			},
			err.Error()))
		return false
	}
	rh := authorization.ResponseHandlerForMode(req.ResponseMode, w, r)
	rh.Error(req.RedirectURI, "access_denied", "", req.State)
	return true
}

func (a *AuthorizationEndpoint) CompleteRequest(w http.ResponseWriter, r *http.Request,
	callbacks bridge.AuthorizationCallbacks) bool {
	req, err := callbacks.Continue()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "Continue",
			},
			err.Error()))
		return false
	}
	rh := authorization.ResponseHandlerForMode(req.ResponseMode, w, r)
	uid, err := callbacks.GetLoginUserId()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "GetLoginUserId",
			},
			err.Error()))
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	info, serr := a.di.CreateOrUpdateAuthInfo(uid, req.ClientId, req.Scope)
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	return a.complete(callbacks, r, rh, info, req)
}

func (a *AuthorizationEndpoint) complete(
	callbacks bridge.AuthorizationCallbacks,
	r *http.Request,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo, req *authorization.Request) bool {
	switch req.Flow.Type {
	case flow.AuthorizationCode:
		return a.completeAuthorizationCodeFlowRequest(callbacks, r, rh, info, req)
	case flow.Implicit:
		return a.completeImplicitFlowRequest(callbacks, r, rh, info, req)
	case flow.Hybrid:
		return a.completeHybridFlowRequest(callbacks, r, rh, info, req)
	}
	return false
}

func (a *AuthorizationEndpoint) completeAuthorizationCodeFlowRequest(
	callbacks bridge.AuthorizationCallbacks,
	r *http.Request,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo,
	req *authorization.Request) bool {
	code, err := callbacks.CreateAuthorizationCode()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "CreateAuthorizationCode",
			},
			err.Error()))
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "GetAuthTime",
			},
			err.Error()))
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}
	serr := a.di.CreateAuthSession(info,
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
	r *http.Request,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo,
	req *authorization.Request) bool {

	clnt, serr := a.di.FindClientById(req.ClientId)
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
		t, serr := a.di.CreateOAuthToken(info, false)
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
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "GetAuthTime",
			},
			err.Error()))
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	if req.Flow.RequireIdToken {
		idt, err := id_token.GenForImplicit(
			clnt.GetIdTokenAlg(),             // id_token signing algorithm
			clnt.GetIdTokenKey(),             // id_token signing key
			clnt.GetIdTokenKeyId(),           // id_token signing key-id
			a.di.Issuer(),                    // issuer
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
	r *http.Request,
	rh authorization.ResponseHandler,
	info bridge.AuthInfo,
	req *authorization.Request) bool {

	code, err := callbacks.CreateAuthorizationCode()

	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "CreateAuthorizationCode",
			},
			err.Error()))
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	authTime, err := callbacks.GetAuthTime()
	if err != nil {
		a.logger.Error(log.AuthorizationEndpointLog(r.URL.Path,
			log.InterfaceError,
			map[string]string{
				"method": "GetAuthTime",
			},
			err.Error()))
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	serr := a.di.CreateAuthSession(info,
		req.ToSession(code, int64(a.policy.AuthSessionExpiresIn), authTime))
	if serr != nil {
		rh.Error(req.RedirectURI, "server_error", "", req.State)
		return false
	}

	clnt, serr := a.di.FindClientById(req.ClientId)
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
		t, serr := a.di.CreateOAuthToken(info, false)
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
			a.di.Issuer(),                    // issuer
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
