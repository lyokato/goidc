package log

import (
	"fmt"
	"strconv"
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
	default:
		return ""
	}
}

func TokenEndpointLog(grantType string, ev LogEvent,
	params map[string]string, msg string) string {
	return EndpointLog("TokenEndpoint", grantType, ev, params, msg)
}

func ProtectedResourceLog(path string, ev LogEvent,
	params map[string]string, msg string) string {
	return EndpointLog("ProtectedResource", path, ev, params, msg)
}

func EndpointLog(endpoint, category string, ev LogEvent,
	params map[string]string, msg string) string {
	attributes := ""
	if params != nil {
		for k, v := range params {
			attributes = attributes + fmt.Sprintf(" %s=%s", k, strconv.Quote(v))
		}
	}
	return fmt.Sprintf("[goidc.%s:%s] <%s%s>: %s", endpoint,
		paint(category, Magenta), paint(ev.String(), Yellow), attributes, msg)
}
