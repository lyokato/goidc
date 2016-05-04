package log

import (
	"encoding/json"
	"fmt"
)

type LogEvent int

const (
	AuthenticationFailed LogEvent = iota
	UnauthorizedGrantType
	AuthInfoConditionMismatch
	ScopeConditionMismatch
	RefreshTokenConditionMismatch
	InterfaceUnsupported
	InterfaceError
	InvalidScope
)

func (e LogEvent) String() string {
	switch e {
	case AuthenticationFailed:
		return "authentication_failed"
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
	case InterfaceError:
		return "interface_error"
	case InvalidScope:
		return "invalid_scope"
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
