package prompt

import "strings"

const (
	None          = "none"
	Login         = "login"
	Consent       = "consent"
	SelectAccount = "select_account"
)

type NoConsentPromptPolicy int

const (
	NoConsentPromptPolicyForceConsent NoConsentPromptPolicy = iota
	NoConsentPromptPolicyOmitConsentIfCan
)

func Split(prompts string) []string {
	return strings.Split(prompts, " ")
}

func IncludeAll(prompts string, targetPrompts []string) (bool, string) {
	list := Split(prompts)
	existanceMap := make(map[string]bool, 0)
	for _, p := range list {
		existanceMap[p] = true
	}
	for _, p := range targetPrompts {
		if _, exists := existanceMap[p]; !exists {
			return false, p
		}
	}
	return true, ""
}

func Include(prompts string, target string) bool {
	list := Split(prompts)
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func Validate(prompts string) bool {
	list := Split(prompts)
	hasNone := false
	hasOther := false
	for _, p := range list {
		switch p {
		case None:
			hasNone = true
		case Login:
			hasOther = true
		case Consent:
			hasOther = true
		case SelectAccount:
			hasOther = true
		default:
			return false
		}
	}
	if hasNone && hasOther {
		return false
	}
	return true
}

func IncludeNone(prompts string) bool {
	return Include(prompts, None)
}

func IncludeLogin(prompts string) bool {
	return Include(prompts, Login)
}

func IncludeConsent(prompts string) bool {
	return Include(prompts, Consent)
}

func IncludeSelectAccount(prompts string) bool {
	return Include(prompts, SelectAccount)
}
