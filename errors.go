package goidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

func NewOAuthError(typeName string, description, uri string) *OAuthError {
	return &OAuthError{typeName, description, uri}
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
