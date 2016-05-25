package authorizer

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type FlowType int

const (
	FlowTypeAuthorizationCode FlowType = iota
	FlowTypeImplicit
	FlowTypeHybrid
	FlowTypeDirectGrant
)

func (ft FlowType) String() string {
	switch ft {
	case FlowTypeAuthorizationCode:
		return "authorization_code"
	case FlowTypeImplicit:
		return "implicit"
	case FlowTypeHybrid:
		return "hybrid"
	case FlowTypeDirectGrant:
		return "direct_grant"
	default:
		panic("shouldn't be here")
	}
}

func (ft FlowType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ft.String() + `"`), nil
}

func (ft *FlowType) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `"authorization_code"`:
		*ft = FlowTypeAuthorizationCode
		return nil
	case `"implicit"`:
		*ft = FlowTypeImplicit
		return nil
	case `"hybrid"`:
		*ft = FlowTypeHybrid
		return nil
	case `"direct_grant"`:
		*ft = FlowTypeDirectGrant
		return nil
	default:
		return errors.New("unknown flow type")
	}
}

type Flow struct {
	Type               FlowType `json:"type"`
	RequireAccessToken bool     `json:"require_access_token"`
	RequireIdToken     bool     `json:"require_id_token"`
}

func JudgeFlowFromResponseType(responseType string) (*Flow, error) {
	list := strings.Split(responseType, " ")
	sort.Strings(list)
	sorted := strings.Join(list, " ")
	switch sorted {
	case "code":
		return &Flow{FlowTypeAuthorizationCode, false, false}, nil
	case "code id_token":
		return &Flow{FlowTypeHybrid, false, true}, nil
	case "code id_token token":
		return &Flow{FlowTypeHybrid, true, true}, nil
	case "code token":
		return &Flow{FlowTypeHybrid, true, false}, nil
	case "id_token":
		return &Flow{FlowTypeImplicit, false, true}, nil
	case "id_token token":
		return &Flow{FlowTypeImplicit, true, true}, nil
	case "token":
		return &Flow{FlowTypeImplicit, true, false}, nil
	case "none":
		return nil, fmt.Errorf("unsupported response type: %s", responseType)
	default:
		return nil, fmt.Errorf("unsupported response type: %s", responseType)
	}
}
