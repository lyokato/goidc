package goidc

import (
	"net/http/httptest"
	"testing"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	sd "github.com/lyokato/goidc/service_data"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointRefreshTokenInvalidRequest(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())
	te.Support(grant.RefreshToken())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)
	client.AllowToUseGrantType(grant.TypeRefreshToken)

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(), "openid profile offline_access",
		&sd.AuthSession{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  "",
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
		})

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	// MISSING REFRESH_TOKEN
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "refresh_token",
			//"refresh_token": "REFRESH_TOKEN_01",
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
			"error_description": th.NewStrMatcher("missing 'refresh_token' parameter"),
		})

	// INVALID REFRESH_TOKEN
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": "INVALID_TOKEN",
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
			"error": th.NewStrMatcher("invalid_grant"),
		})

	// use AuthorizationCode and create AccessToken and RefreshToken
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
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		map[string]th.Matcher{
			"iss": th.NewStrMatcher("example.org"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})

	// now refresh token should exists
	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": "REFRESH_TOKEN_0",
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
			"access_token":  th.NewStrMatcher("ACCESS_TOKEN_0:R"),
			"refresh_token": th.NewStrMatcher("REFRESH_TOKEN_0"),
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		nil)

	// refresh again
	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": "REFRESH_TOKEN_0",
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
			"access_token":  th.NewStrMatcher("ACCESS_TOKEN_0:R:R"),
			"refresh_token": th.NewStrMatcher("REFRESH_TOKEN_0"),
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		nil)

}
