package flow

import (
	"fmt"
	"sort"
	"strings"
)

const (
	FlowTypeBasic    = "basic"
	FlowTypeImplicit = "implicit"
	FlowTypeHybrid   = "hybrid"
)

type (
	Flow struct {
		Type        string `json:"type"`
		NeedToken   bool   `json:"need_token"`
		NeedIDToken bool   `json:"need_id_token"`
	}
)

func JudgeFlowFromResponseType(responseType string) (*Flow, error) {
	list := strings.Split(responseType, " ")
	sort.Strings(list)
	sorted := strings.Join(list, " ")
	switch sorted {
	case "code":
		return &Flow{FlowTypeBasic, false, false}, nil
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
