package goidc

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/crypto"
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

	th.TokenEndpointErrorTest(t, ts,
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
		},
		map[string]th.Matcher{
			"error": th.NewStrMatcher("server_error"),
		})
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

	th.TokenEndpointSuccessTest(t, ts,
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
		},
		map[string]th.Matcher{
			"access_token":  th.NewStrMatcher("ACCESS_TOKEN_0"),
			"refresh_token": th.NewStrMatcher("REFRESH_TOKEN_0"),
			"expires_in":    th.NewInt64RangeMatcher(0, time.Now().Unix()),
		},
		nil)
}

func TestTokenEndpointAuthorizationCodeGrant02(t *testing.T) {

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

	idt, err := jwt.Parse(id_token_origin, func(token *jwt.Token) (interface{}, error) {
		return crypto.LoadPublicKeyFromText(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)
	})
	if err != nil {
		t.Errorf("failed to parse token %s", err)
		return
	}
	if !idt.Valid {
		t.Error("id_token is not valid")
	}
	actual = idt.Claims["aud"].(string)
	expected = "client_id_01"
	if actual != expected {
		t.Errorf("aud:\n - got: %v\n - want: %v\n", actual, expected)
	}
}
