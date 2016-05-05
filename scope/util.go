package scope

import "strings"

const (
	OpenID        = "openid"
	Email         = "email"
	OfflineAccess = "offline_access"
)

func Split(scope string) []string {
	return strings.Split(scope, " ")
}

func IncludeAll(scopes string, targetScopes []string) (bool, string) {
	list := Split(scopes)
	existanceMap := make(map[string]bool, 0)
	for _, s := range list {
		existanceMap[s] = true
	}
	for _, s := range targetScopes {
		if _, exists := existanceMap[s]; !exists {
			return false, s
		}
	}
	return true, ""
}

func Include(scopes string, targetScope string) bool {
	list := Split(scopes)
	for _, s := range list {
		if s == targetScope {
			return true
		}
	}
	return false
}

func IncludeOpenID(scopes string) bool {
	return Include(scopes, OpenID)
}

func IncludeOfflineAccess(scopes string) bool {
	return Include(scopes, OfflineAccess)
}
