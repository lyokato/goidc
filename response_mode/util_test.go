package response_mode

import (
	"testing"
)

func TestCompareSecurityLevel(t *testing.T) {
	defaultRM := Query // flow.AuthorizationCode
	if !CompareSecurityLevel(Query, defaultRM) {
		t.Error("CompareSecurityLevel should be ok")
	}
	if !CompareSecurityLevel(Fragment, defaultRM) {
		t.Error("CompareSecurityLevel should be ok")
	}
	if !CompareSecurityLevel(FormPost, defaultRM) {
		t.Error("CompareSecurityLevel should be ok")
	}

	defaultRM = Fragment // flow.Implicit or flow.Hybrid
	if CompareSecurityLevel(Query, defaultRM) {
		t.Error("CompareSecurityLevel should not be ok")
	}
	if !CompareSecurityLevel(Fragment, defaultRM) {
		t.Error("CompareSecurityLevel should be ok")
	}
	if !CompareSecurityLevel(FormPost, defaultRM) {
		t.Error("CompareSecurityLevel should be ok")
	}
}

