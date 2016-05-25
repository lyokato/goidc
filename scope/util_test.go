package scope

import "testing"

func TestInclude(t *testing.T) {

	origin := "openid email custom"
	if !Include(origin, OpenID) {
		t.Error("'openid' should be found")
	}

	if !IncludeOpenID(origin) {
		t.Error("'openid' should be found")
	}

	if !Include(origin, Email) {
		t.Error("'email' should be found")
	}

	if Include(origin, "unknown") {
		t.Error("'unknown' should be found")
	}

	origin = "custom offline_access"
	if Include(origin, OpenID) {
		t.Error("'openid' shouldn't be found")
	}

	if !IncludeOfflineAccess(origin) {
		t.Error("'offline_access' should be found")
	}
}

func TestIncludeAll(t *testing.T) {

	targetScope := []string{"profile", "custom1"}
	included, _ := IncludeAll("openid profile custom1 custom2", targetScope)
	if !included {
		t.Error("IncludeAll should success")
	}

	included, not_found := IncludeAll("openid profile custom2", targetScope)
	if included {
		t.Error("IncludeAll should fail")
	}
	expected := "custom1"
	if not_found != expected {
		t.Errorf("NotFound:\n - got: %v\n - want: %v\n", not_found, expected)
	}
}

func TestRemove(t *testing.T) {
	origin := "openid email offline_access"
	removed := Remove(origin, OpenID)
	if removed != "email offline_access" {
		t.Error("removed scope should be 'email offline_access'")
	}

	removed = RemoveOfflineAccess(origin)
	if removed != "openid email" {
		t.Error("removed scope should be 'openid email'")
	}
}
