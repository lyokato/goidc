package authorizer

import "github.com/lyokato/goidc/flow"

const (
	DisplayTypePopup = "popup"
	DisplayTypeTouch = "touch"
	DisplayTypeWAP   = "wap"
	DisplayTypePage  = "page"

	PromptTypeDefault       = ""
	PromptTypeNone          = "none"
	PromptTypeLogin         = "login"
	PromptTypeSelectAccount = "select_account"
	PromptTypeConsent       = "consent"
)

type (
	Request struct {
		/*
			FlowType     string   `json:"flow_type"`
			NeedToken    bool     `json:"need_token"`
			NeedIDToken  bool     `json:"need_id_token"`
		*/
		Flow         *flow.Flow `json:"flow"`
		ClientId     string     `json:"client_id"`
		Scope        string     `json:"scope"`
		RedirectURI  string     `json:"redirect_uri"`
		State        string     `json:"state"`
		CodeVerifier string     `json:"code_verifier"`
		Nonce        string     `json:"nonce"`
		Display      string     `json:"display"`
		Prompt       string     `json:"prompt"`
		MaxAge       int        `json:"max_age"`
		UILocales    string     `json:"ui_locales"`
		IDTokenHint  string     `json:"id_token_hint"`
		LoginHint    string     `json:"login_hint"`
	}
)
