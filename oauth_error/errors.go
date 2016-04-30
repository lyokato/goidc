package oauth_error

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-querystring/query"
)

type OAuthErrorURIBuilder func(string) string

const (
	// RFC6749
	ErrAccessDenied            = "access_denied"
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrInvalidRequest          = "invalid_request"
	ErrInvalidScope            = "invalid_scope"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"

	// RFC6750
	ErrInvalidToken      = "invalid_token"
	ErrInsufficientScope = "insufficient_scope"

	// OpenID Core 3.1.2.6 Authentication Error Response
	ErrInteractionRequired      = "interaction_required"
	ErrLoginRequired            = "login_required"
	ErrAccountSelectionRequired = "account_selection_required"
	ErrConsentRequired          = "consent_required"
	ErrInvalidRequestURI        = "invalid_request_uri"
	ErrInvalidRequestObject     = "invalid_request_object"
	ErrRequestNotSupported      = "request_not_supported"
	ErrRequestURINotSupported   = "request_uri_not_supported"
	ErrRegistrationNotSupported = "registration_not_supported"
)

var errStatusCodeMap = map[string]int{
	ErrAccessDenied:            http.StatusForbidden,
	ErrInvalidClient:           http.StatusBadRequest,
	ErrInvalidGrant:            http.StatusBadRequest,
	ErrInvalidRequest:          http.StatusBadRequest,
	ErrInvalidScope:            http.StatusBadRequest,
	ErrUnauthorizedClient:      http.StatusUnauthorized,
	ErrUnsupportedGrantType:    http.StatusBadRequest,
	ErrUnsupportedResponseType: http.StatusBadRequest,
	ErrServerError:             http.StatusInternalServerError,
}

/*
type AuthorizationRequestError struct {
	Type        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"uri"`
	State       string `json:"state"`
}
*/

type OAuthError struct {
	Type        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"uri,omitempty"`
}

type OAuthErrorQuery struct {
	Type        string `url:"error"`
	Description string `url:"error_description,omitempty"`
	URI         string `url:"uri,omitempty"`
	State       string `url:"state,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Type
	} else {
		return fmt.Sprintf("%s: %s", e.Type, e.Description)
	}
}

func (e *OAuthError) StatusCode() int {
	code, exists := errStatusCodeMap[e.Type]
	if exists {
		return code
	} else {
		return http.StatusInternalServerError
	}
}

func NewOAuthError(typeName, description, uri string) *OAuthError {
	return &OAuthError{typeName, description, uri}
}

func NewOAuthSimpleError(typeName string) *OAuthError {
	return &OAuthError{typeName, "", ""}
}

func (e *OAuthError) JSON() []byte {
	body, err := json.Marshal(e)
	if err != nil {
		// must not come here
		panic(fmt.Sprintf("broken JSON: %s", err))
	}
	return body
}

func (e *OAuthError) Header(realm string) string {
	params := make([]string, 0)
	if realm != "" {
		params = append(params, fmt.Sprintf("realm=\"%s\"", realm))
	}
	params = append(params, fmt.Sprintf("error=\"%s\"", e.Type))
	if e.Description != "" {
		params = append(params, fmt.Sprintf("error_description=\"%s\"", e.Description))
	}
	if e.URI != "" {
		params = append(params, fmt.Sprintf("error_uri=\"%s\"", e.URI))
	}
	return "Bearer " + strings.Join(params, ", ")
}

func (e *OAuthError) Query(state string) string {
	v, err := query.Values(&OAuthErrorQuery{
		Type:        e.Type,
		Description: e.Description,
		URI:         e.URI,
		State:       state,
	})
	if err != nil {
		// must not come here
		panic(fmt.Sprintf("broken QueryString: %s", err))
	}
	return v.Encode()
}
