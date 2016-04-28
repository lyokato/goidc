package flow

import (
	"fmt"
	"sort"
	"strings"
)

const (
	FlowTypeBasic    = 0
	FlowTypeImplicit = 1
	FlowTypeHybrid   = 2
)

type (
	Flow struct {
		Type        int
		NeedToken   bool
		NeedIDToken bool
	}
)

func JudgeFlowFromResponseType(responseType string) (*Flow, error) {
	list := strings.Split(responseType, " ")
	sort.Strings(list)
	sorted := strings.Join(list, " ")
	switch sorted {
	case "code":
		return &Flow{FlowTypeBasic, true, true}, nil
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
