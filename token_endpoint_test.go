package goidc

import (
	"net/http/httptest"
	"testing"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointAuthorizationCodeGrant(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())
	te.Support(grant.RefreshToken())

	sdi := th.NewTestStore()

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	result := th.PostFormValueRequestWithJSONResponse(t, ts,
		map[string]string{
			"grant_type": "authorization_code",
		},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_000", "client_secret_000"),
		},
		500,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		})

	actual_error := result["error"].(string)
	expected_error := "server_error"
	if actual_error != expected_error {
		t.Errorf("error:\n - got: %v\n - want: %v\n", actual_error, expected_error)
	}
	//actual_expies_in := result["expires_in"].(int)
}
