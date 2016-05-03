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
	attributes := ""
	if params != nil {
		for k, v := range params {
			attributes = attributes + fmt.Sprintf(" %s='%s'", k, v)
		}
	}
	return fmt.Sprintf("[goidc.TokenEndpoint:%s] <%s%s>: %s", grantType, ev.String(), attributes, msg)
}
