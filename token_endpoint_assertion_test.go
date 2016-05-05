package goidc

import (
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/lyokato/goidc/grant"
	sd "github.com/lyokato/goidc/service_data"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointInvalidClientAssertion(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())
	te.Support(grant.Password())
	te.Support(grant.ClientCredentials())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType("authorization_code")

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(), "openid profile offline_access",
		&sd.AuthSession{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  "",
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
		})

	key := client.AssertionKey("", "")
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"

	assertion, err := token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type":            "authorization_code",
			"code":                  "code_value",
			"redirect_uri":          "http://example.org/callback",
			"client_assertion":      assertion,
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		},
		map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
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
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		map[string]th.Matcher{
			"iss": th.NewStrMatcher("http://example.org/"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})
}
