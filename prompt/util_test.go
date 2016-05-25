package prompt

import "testing"

func TestInclude(t *testing.T) {
	prompt := "none consent"

	if !IncludeNone(prompt) {
		t.Error("IncludeNone should be ok")
	}

	if !IncludeConsent(prompt) {
		t.Error("IncludeConsent should be ok")
	}

	if IncludeLogin(prompt) {
		t.Error("IncludeLogin should not be ok")
	}

	if !Validate("consent login") {
		t.Error("Validate returns ok with 'consent login'")
	}

	if Validate("none consent") {
		t.Error("Validate returns not ok with 'none consent'")
	}

	if !Validate("none") {
		t.Error("Validate returns ok with 'none'")
	}
}
