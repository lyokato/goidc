package goidc

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	th "github.com/lyokato/goidc/test_helper"
)

// TODO invalid grant
// TODO invalid client
func TestTokenEndpointAuthorizationCodeGrant00(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

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

func TestTokenEndpointAuthorizationCodeGrant01(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "clinet_secret_01", "http://example.org/callback")

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(),
		"http://example.org/callback", strconv.FormatInt(user.Id, 10), "openid profile offline_access",
		time.Now().Unix(), "code_value", int64(60*60*24), "", "07dfa90f")

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	result := th.PostFormValueRequestWithJSONResponse(t, ts,
		map[string]string{
			"grant_type":   "authorization_code",
			"code":         "code_value",
			"redirect_uri": "http://example.org/callback",
		},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_01", "client_secret_01"),
		},
		200,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		})

	actual := result["access_token"].(string)
	expected := "ACCESS_TOKEN_0"
	if actual != expected {
		t.Errorf("token:\n - got: %v\n - want: %v\n", actual, expected)
	}
	//actual_expies_in := result["expires_in"].(int)
}
