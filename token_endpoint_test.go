package goidc

import (
	"net/http/httptest"
	"strconv"
	"strings"
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
		t.Errorf("access_token:\n - got: %v\n - want: %v\n", actual, expected)
	}

	id_token_origin := result["id_token"].(string)
	id_token_parts := strings.Split(id_token_origin, ".")
	if len(id_token_parts) != 3 {
		t.Error("id_token parts should be 3")
		return
	}
	/*
		id_token_header, _ := base64.StdEncoding.DecodeString(id_token_parts[0])
		actual = string(id_token_header)
		expected = "{\"alg\":\"RS256\",\"kid\":\"my_service_key_id\"}"

		if actual != expected {
			t.Errorf("id_token_header:\n - got: %s\n - want: %v\n", actual, expected)
		}

		id_token_body, _ := base64.StdEncoding.DecodeString(id_token_parts[1])
		actual = string(id_token_body)
		expected = ""

		if actual != expected {
			t.Errorf("id_token_body:\n - got: %s\n - want: %v\n", actual, expected)
		}

		id_token_sign, _ := base64.StdEncoding.DecodeString(id_token_parts[2])
		actual = string(id_token_sign)
		expected = ""

		if actual != expected {
			t.Errorf("id_token_sign:\n - got: %v\n - want: %v\n", actual, expected)
		}
	*/
}
