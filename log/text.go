package log

import (
	"encoding/json"
	"fmt"
)

type LogEvent int

const (
	AuthenticationFailed LogEvent = iota
	CodeChallengeFailed
	UnauthorizedGrantType
	AuthInfoConditionMismatch
	ScopeConditionMismatch
	RefreshTokenConditionMismatch
	InterfaceUnsupported
	InterfaceServerError
	InterfaceError
	InvalidScope
	AccessTokenGranted
	InvalidHTTPMethod
	MissingParam
	UnsupportedGrantType
	UnsupportedCodeChallengeMethod
	NoCredential
	NoEnabledClient
	NoEnabledAuthInfo
	AccessTokenCreationFailed
	IdTokenGeneration
)

func (e LogEvent) String() string {
	switch e {
	case AuthenticationFailed:
		return "authentication_failed"
	case CodeChallengeFailed:
		return "code_challenge_failed"
	case UnauthorizedGrantType:
		return "unauthorized_grant_type"
	case ScopeConditionMismatch:
		return "scope_condition_mismatch"
	case RefreshTokenConditionMismatch:
		return "refresh_token_condition_mismatch"
	case AuthInfoConditionMismatch:
		return "auth_info_condition_mismatch"
	case InterfaceUnsupported:
		return "interface_unsupported"
	case InterfaceServerError:
		return "interface_server_error"
	case InterfaceError:
		return "interface_error"
	case InvalidScope:
		return "invalid_scope"
	case AccessTokenGranted:
		return "access_token_granted"
	case AccessTokenCreationFailed:
		return "access_token_creation_failed"
	case InvalidHTTPMethod:
		return "invalid_http_method"
	case MissingParam:
		return "missing_param"
	case UnsupportedGrantType:
		return "unsupported_grant_type"
	case UnsupportedCodeChallengeMethod:
		return "unsupported_code_challenge_method"
	case NoCredential:
		return "no_credential"
	case NoEnabledClient:
		return "no_enabled_client"
	case NoEnabledAuthInfo:
		return "no_enabled_auth_info"
	case IdTokenGeneration:
		return "id_token_generation"
	default:
		return ""
	}
}

func TokenEndpointLog(grantType string, ev LogEvent,
	params map[string]string, msg string) string {
	return EndpointLog("token_endpoint", grantType, ev, params, msg)
}

func ProtectedResourceLog(path string, ev LogEvent,
	params map[string]string, msg string) string {
	return EndpointLog("protected_resource", path, ev, params, msg)
}

func EndpointLog(endpoint, realm string, ev LogEvent,
	params map[string]string, msg string) string {
	attributes, _ := json.Marshal(params)
	return fmt.Sprintf("[goidc:%s:%s:%s] %s %s", endpoint,
		lightPaint(realm, Blue), paint(ev.String(), Cyan), msg, lightPaint(string(attributes), Red))
}
