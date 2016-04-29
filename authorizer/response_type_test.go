package authorizer

import "testing"

func TestFlow(t *testing.T) {
	_, err := JudgeFlowFromResponseType("invalid code")
	if err == nil {
		t.Error("invalid repsonse_type should fail")
	}
	str1 := "code token"
	flow, err := JudgeFlowFromResponseType(str1)
	if err != nil {
		t.Error("failed to judge flow")
	}
	if flow.Type != FlowTypeHybrid {
		t.Errorf("'code token' should be hybrid")
	}

	if !flow.NeedToken {
		t.Error("'code token' requires token")
	}

	if flow.NeedIDToken {
		t.Error("'code token' doesn't requires id_token")
	}
}
