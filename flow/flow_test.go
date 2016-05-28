package flow

import (
	"encoding/json"
	"testing"
)

func TestFlowJSON(t *testing.T) {
	str1 := "code token"
	flow, _ := JudgeFromResponseType(str1)
	b, _ := json.Marshal(flow)
	actual := string(b)
	expected := `{"type":"hybrid","require_access_token":true,"require_id_token":false}`
	if actual != expected {
		t.Errorf("flow JSON:\n - got: %v\n - want: %v\n", actual, expected)
	}

	var f Flow
	json.Unmarshal([]byte(expected), &f)

	if f.Type != Hybrid {
		t.Errorf("'code token' should be hybrid: %v", f)
	}

	if !f.RequireAccessToken {
		t.Error("'code token' requires access token")
	}

	if f.RequireIdToken {
		t.Error("'code token' doesn't requires id_token")
	}
}

func TestFlow(t *testing.T) {
	_, err := JudgeFromResponseType("invalid code")
	if err == nil {
		t.Error("invalid repsonse_type should fail")
	}
	str1 := "code token"
	flow, err := JudgeFromResponseType(str1)
	if err != nil {
		t.Error("failed to judge flow")
	}
	if flow.Type != Hybrid {
		t.Errorf("'code token' should be hybrid")
	}

	if !flow.RequireAccessToken {
		t.Error("'code token' requires access token")
	}

	if flow.RequireIdToken {
		t.Error("'code token' doesn't requires id_token")
	}

	str2 := "code"
	flow, err = JudgeFromResponseType(str2)
	if err != nil {
		t.Error("failed to judge flow")
	}
	if flow.Type != AuthorizationCode {
		t.Errorf("'code token' should be hybrid")
	}

	if flow.RequireAccessToken {
		t.Error("'code token' requires access token")
	}

	if flow.RequireIdToken {
		t.Error("'code token' doesn't requires id_token")
	}
}
