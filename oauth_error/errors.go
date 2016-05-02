package oauth_error

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-querystring/query"
)

type OAuthErrorType int
type OAuthErrorURIBuilder func(OAuthErrorType) string

const (
	// RFC6749
	ErrAccessDenied OAuthErrorType = iota
	ErrInvalidClient
	ErrInvalidGrant
	ErrInvalidRequest
	ErrInvalidScope
	ErrUnauthorizedClient
	ErrUnsupportedGrantType
	ErrUnsupportedResponseType
	ErrServerError
	ErrTemporarilyUnavailable
	// RFC6750
	ErrInvalidToken
	ErrInsufficientScope
	// OpenID Core 3.1.2.6 Authentication Error Response
	ErrInteractionRequired
	ErrLoginRequired
	ErrAccountSelectionRequired
	ErrConsentRequired
	ErrInvalidRequestURI
	ErrInvalidRequestObject
	ErrRequestNotSupported
	ErrRequestURINotSupported
	ErrRegistrationNotSupported
)

var errStatusCodeMap = map[OAuthErrorType]int{
	ErrAccessDenied:            http.StatusForbidden,
	ErrInvalidClient:           http.StatusBadRequest,
	ErrInvalidGrant:            http.StatusBadRequest,
	ErrInvalidRequest:          http.StatusBadRequest,
	ErrInvalidScope:            http.StatusBadRequest,
	ErrUnauthorizedClient:      http.StatusBadRequest,
	ErrUnsupportedGrantType:    http.StatusBadRequest,
	ErrUnsupportedResponseType: http.StatusBadRequest,
	ErrServerError:             http.StatusInternalServerError,
}

func (t OAuthErrorType) String() string {
	switch t {
	case ErrAccessDenied:
		return "access_denied"
	case ErrInvalidClient:
		return "invalid_client"
	case ErrInvalidGrant:
		return "invalid_grant"
	case ErrInvalidRequest:
		return "invalid_request"
	case ErrInvalidScope:
		return "invalid_scope"
	case ErrUnauthorizedClient:
		return "unauthorized_client"
	case ErrUnsupportedGrantType:
		return "unsupported_grant_type"
	case ErrUnsupportedResponseType:
		return "unsupported_response_type"
	case ErrServerError:
		return "server_error"
	case ErrTemporarilyUnavailable:
		return "temporarily_unavailable"

	case ErrInvalidToken:
		return "invalid_token"
	case ErrInsufficientScope:
		return "insufficient_scope"

	// OpenID Core 3.1.2.6 Authentication Error Response
	case ErrInteractionRequired:
		return "interaction_required"
	case ErrLoginRequired:
		return "login_required"
	case ErrAccountSelectionRequired:
		return "account_selection_required"
	case ErrConsentRequired:
		return "consent_required"
	case ErrInvalidRequestURI:
		return "invalid_request_uri"
	case ErrInvalidRequestObject:
		return "invalid_request_object"
	case ErrRequestNotSupported:
		return "request_not_supported"
	case ErrRequestURINotSupported:
		return "request_uri_not_supported"
	case ErrRegistrationNotSupported:
		return "registration_not_supported"
	}
	return ""
}

type OAuthError struct {
	Type        OAuthErrorType
	Description string
	URI         string
}

type OAuthErrorJSON struct {
	Type        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

type OAuthErrorQuery struct {
	Type        string `url:"error"`
	Description string `url:"error_description,omitempty"`
	URI         string `url:"error_uri,omitempty"`
	State       string `url:"state,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Type.String()
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

func NewOAuthError(typeName OAuthErrorType, description string) *OAuthError {
	return &OAuthError{typeName, description, ""}
}

func NewOAuthSimpleError(typeName OAuthErrorType) *OAuthError {
	return &OAuthError{typeName, "", ""}
}

func NewOAuthDetailedError(typeName OAuthErrorType, description, uri string) *OAuthError {
	return &OAuthError{typeName, description, uri}
}

func (e *OAuthError) JSON() []byte {
	j := &OAuthErrorJSON{
		Type:        e.Type.String(),
		Description: e.Description,
		URI:         e.URI,
	}
	body, err := json.Marshal(j)
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
	params = append(params, fmt.Sprintf("error=\"%s\"", e.Type.String()))
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
		Type:        e.Type.String(),
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
