package response_mode

const (
	Query    = "query"
	Fragment = "fragment"
	FormPost = "form_post"
)

func Validate(mode string) bool {
	return mode == Query || mode == Fragment || mode == FormPost
}

func securityLevelForMode(mode string) int {
	switch mode {
	case Query:
		return 0
	case Fragment:
		return 1
	case FormPost:
		return 2
	}
	return -1
}

func CompareSecurityLevel(targetMode, defaultMode string) bool {
	return securityLevelForMode(targetMode) >= securityLevelForMode(defaultMode)
}
