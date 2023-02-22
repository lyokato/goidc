package goidc

import (
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointJWT(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.JWT())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeJWT)

	key := client.GetAssertionKey("", "")
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["aud"] = "http://example.org/"
	claims["iss"] = "http://client.example.org/"
	claims["sub"] = "user01"
	claims["exp"] = time.Now().Unix() + 60*60*24
	token.Claims = claims
	assertion, err := token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"scope":      "offline_access",
			"assertion":  assertion,
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
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		nil)

}

func TestTokenEndpointJWTInvalidRequest(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.JWT())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeJWT)

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	// missing username
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			"scope":      "offline_access",
		},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_01", "client_secret_01"),
		},
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("missing 'assertion' parameter"),
		})

}
