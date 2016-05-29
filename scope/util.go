package scope

import (
	"sort"
	"strings"
)

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

func Remove(scopes string, targetScope string) string {
	list := Split(scopes)
	newList := make([]string, 0)
	for _, s := range list {
		if s != targetScope {
			newList = append(newList, s)
		}
	}
	return strings.Join(newList, " ")
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

func Same(scope1, scope2 string) bool {
	return Sort(scope1) == Sort(scope2)
}

func Sort(origin string) string {
	list := Split(origin)
	sort.Strings(list)
	return strings.Join(list, " ")
}

func IncludeOpenID(scopes string) bool {
	return Include(scopes, OpenID)
}

func IncludeOfflineAccess(scopes string) bool {
	return Include(scopes, OfflineAccess)
}

func RemoveOpenID(scopes string) string {
	return Remove(scopes, OpenID)
}

func RemoveOfflineAccess(scopes string) string {
	return Remove(scopes, OfflineAccess)
}
