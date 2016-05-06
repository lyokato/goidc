package goidc

import (
	"net/http/httptest"
	"testing"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	sd "github.com/lyokato/goidc/service_data"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointAuthorizationCodePKCE(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	code_verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(), "openid profile offline_access",
		&sd.AuthSession{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  code_verifier,
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
		})

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	// MISSING code challenge method
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":     "authorization_code",
			"code":           "code_value",
			"redirect_uri":   "http://example.org/callback",
			"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
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
			"error_description": th.NewStrMatcher("missing 'code_challenge_method' parameter"),
		})

	// MISSING code challenge
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":            "authorization_code",
			"code":                  "code_value",
			"redirect_uri":          "http://example.org/callback",
			"code_challenge_method": "plain",
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
			"error_description": th.NewStrMatcher("missing 'code_challenge' parameter"),
		})

	// INVALID challenge method
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":            "authorization_code",
			"code":                  "code_value",
			"redirect_uri":          "http://example.org/callback",
			"code_challenge_method": "unknown",
			"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
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
			"error_description": th.NewStrMatcher("unsupported 'code_challenge_method': 'unknown'"),
		})

	// INVALID code challenge
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":            "authorization_code",
			"code":                  "code_value",
			"redirect_uri":          "http://example.org/callback",
			"code_challenge_method": "S256",
			"code_challenge":        "A9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
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
			"error":             th.NewStrMatcher("invalid_grant"),
			"error_description": th.NewStrMatcher("invalid 'code_challenge': 'A9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'"),
		})

	// VALID CODE for S256
	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type":            "authorization_code",
			"code":                  "code_value",
			"redirect_uri":          "http://example.org/callback",
			"code_challenge_method": "S256",
			"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
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
			"iss": th.NewStrMatcher("http://example.org/"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})

	// VALID CODE for plain
	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type":            "authorization_code",
			"code":                  "code_value",
			"redirect_uri":          "http://example.org/callback",
			"code_challenge_method": "plain",
			"code_challenge":        code_verifier,
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
			"iss": th.NewStrMatcher("http://example.org/"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})
}

func TestTokenEndpointAuthorizationCodeInvalidRequest(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

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

	// MISSING REDIRECT_URI
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "authorization_code",
			"code":       "code_value",
			//"redirect_uri": "http://example.org/callback",
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
			"error_description": th.NewStrMatcher("missing 'redirect_uri' parameter"),
		})

	// INVALID REDIRECT_URI
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":   "authorization_code",
			"code":         "code_value",
			"redirect_uri": "http://example.org/invalid",
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

	// MISSING CODE
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "authorization_code",
			//"code":       "code_value",
			"redirect_uri": "http://example.org/callback",
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
			"error_description": th.NewStrMatcher("missing 'code' parameter"),
		})

	// INVALID CODE
	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":   "authorization_code",
			"code":         "invalid_code_value",
			"redirect_uri": "http://example.org/callback",
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
}

func TestTokenEndpointAuthorizationCode(t *testing.T) {

	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

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
			"iss": th.NewStrMatcher("http://example.org/"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})

	th.TokenEndpointSuccessTest(t, ts,
		map[string]string{
			"grant_type":    "authorization_code",
			"code":          "code_value",
			"redirect_uri":  "http://example.org/callback",
			"client_id":     "client_id_01",
			"client_secret": "client_secret_01",
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

func TestTokenEndpointAuthorizationCodeWithoutOfflineAccess(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(), "openid profile",
		&sd.AuthSession{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  "",
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
		})

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
			"refresh_token": th.NewAbsentMatcher(),
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		map[string]th.Matcher{
			"iss": th.NewStrMatcher("http://example.org/"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})
}

func TestTokenEndpointAuthorizationCodeWithoutOpenID(t *testing.T) {
	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(), "profile offline_access",
		&sd.AuthSession{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  "",
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
		})

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
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
			"id_token":      th.NewAbsentMatcher(),
		},
		nil)
}
