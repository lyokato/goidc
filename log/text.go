package log

import "fmt"

type TokenEndpointLogEvent int

const (
	ClientAuthenticationFailed TokenEndpointLogEvent = iota
	AuthInfoConditionMismatch
	ScopeConditionMismatch
	RefreshTokenConditionMismatch
	InterfaceUnsupported
	InterfaceError
)

func (e TokenEndpointLogEvent) String() string {
	switch e {
	case ClientAuthenticationFailed:
		return "ClientAuthenticationFailed"
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

func TokenEndpointLog(grantType string, ev TokenEndpointLogEvent,
	params map[string]string, msg string) string {
	return EndpointLog("TokenEndpoint", grantType, ev, params, msg)
}

func ProtectedResourceLog(path string, ev TokenEndpointLogEvent,
	params map[string]string, msg string) string {
	return EndpointLog("ProtectedResource", path, ev, params, msg)
}

func EndpointLog(endpoint, grantType string, ev TokenEndpointLogEvent,
	params map[string]string, msg string) string {
	attributes := ""
	if params != nil {
		for k, v := range params {
			attributes = attributes + fmt.Sprintf(" %s='%s'", k, v)
		}
	}
	return fmt.Sprintf("[goidc.%s:%s] <%s%s>: %s", endpoint, grantType, ev.String(), attributes, msg)
}
