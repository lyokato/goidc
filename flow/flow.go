package flow

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type FlowType int

const (
	AuthorizationCode FlowType = iota
	Implicit
	Hybrid
	DirectGrant
)

func (ft FlowType) String() string {
	switch ft {
	case AuthorizationCode:
		return "authorization_code"
	case Implicit:
		return "implicit"
	case Hybrid:
		return "hybrid"
	case DirectGrant:
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
		*ft = AuthorizationCode
		return nil
	case `"implicit"`:
		*ft = Implicit
		return nil
	case `"hybrid"`:
		*ft = Hybrid
		return nil
	case `"direct_grant"`:
		*ft = DirectGrant
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

func JudgeByResponseType(responseType string) (*Flow, error) {
	list := strings.Split(responseType, " ")
	sort.Strings(list)
	sorted := strings.Join(list, " ")
	switch sorted {
	case "code":
		return &Flow{AuthorizationCode, false, false}, nil
	case "code id_token":
		return &Flow{Hybrid, false, true}, nil
	case "code id_token token":
		return &Flow{Hybrid, true, true}, nil
	case "code token":
		return &Flow{Hybrid, true, false}, nil
	case "id_token":
		return &Flow{Implicit, false, true}, nil
	case "id_token token":
		return &Flow{Implicit, true, true}, nil
	case "token":
		return &Flow{Implicit, true, false}, nil
	case "none":
		return nil, fmt.Errorf("unsupported response type: %s", responseType)
	default:
		return nil, fmt.Errorf("unsupported response type: %s", responseType)
	}
}
