package scope

import "strings"

const (
	OpenID = "openid"
	Email  = "email"
)

func Split(scope string) []string {
	return strings.Split(scope, " ")
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
