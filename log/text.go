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
		return "AuthenticationFailed"
	case UnauthorizedGrantType:
		return "UnauthorizedGrantType"
	case ScopeConditionMismatch:
		return "ScopeConditionMismatch"
	case RefreshTokenConditionMismatch:
		return "RefreshTokenConditionMismatch"
	case AuthInfoConditionMismatch:
		return "AuthInfoConditionMismatch"
	case InterfaceUnsupported:
		return "InterfaceUnsupported"
	case InterfaceError:
		return "InterfaceError"
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
	return fmt.Sprintf("[goidc.%s:%s] <%s%s>: %s", endpoint, category, ev.String(), attributes, msg)
}
