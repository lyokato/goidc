package goidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointNonPostRequest(t *testing.T) {
	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())
	sdi := th.NewTestStore()
	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	var methods = []string{"GET", "HEAD", "PUT", "DELETE", "OPTIONS"}

	c := http.DefaultClient
	for _, method := range methods {
		r, err := http.NewRequest(method, ts.URL, nil)
		if err != nil {
			t.Errorf("failed to build %s request: %s", method, err)
			continue
		}
		resp, err := c.Do(r)
		if err != nil {
			t.Errorf("failed http %s request: %s", method, err)
			continue
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s request returns status code, which is not 405 - Method not allowed", method)
			continue
		}
	}
}

func TestTokenEndpointErrorURIBuilder(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()

	te.SetErrorURI("http://example.org/error")
	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_000", "client_secret_000"),
		},
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("missing 'grant_type' parameter"),
			"error_uri":         th.NewStrMatcher("http://example.org/error"),
		})

	te.SetErrorURIBuilder(func(errorType string) string {
		return fmt.Sprintf("http://example.org/error#%s", errorType)
	})

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_000", "client_secret_000"),
		},
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("missing 'grant_type' parameter"),
			"error_uri":         th.NewStrMatcher("http://example.org/error#invalid_request"),
		})
}

func TestTokenEndpointInvalidGrantType(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_000", "client_secret_000"),
		},
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("missing 'grant_type' parameter"),
		})

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "refresh_token",
		},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_000", "client_secret_000"),
		},
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("unsupported_grant_type"),
			"error_description": th.NewStrMatcher("unsupported 'grant_type' parameter: 'refresh_token'"),
		})
}

func TestTokenEndpointInvalidClient(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())
	te.Support(grant.Password())
	te.Support(grant.ClientCredentials())

	sdi := th.NewTestStore()
	sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType("authorization_code")

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type":    "authorization_code",
			"client_id":     "client_id_000",
			"client_secret": "client_secret_000",
		},
		map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
		},
		401,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error": th.NewStrMatcher("invalid_client"),
		})

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "authorization_code",
		},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": basic_auth.Header("client_id_000", "client_secret_000"),
		},
		401,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error": th.NewStrMatcher("invalid_client"),
		})
}

func TestTokenEndpointUnauthorizedClient(t *testing.T) {

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())
	te.Support(grant.Password())
	te.Support(grant.ClientCredentials())

	sdi := th.NewTestStore()
	sdi.CreateNewUser("user01", "pass01")
	sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")

	ts := httptest.NewServer(te.Handler(sdi))
	defer ts.Close()

	th.TokenEndpointErrorTest(t, ts,
		map[string]string{
			"grant_type": "authorization_code",
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
			"error": th.NewStrMatcher("unauthorized_client"),
		})
}

func TestTokenEndpointAuthorizationCodeInvalidPKCE(t *testing.T) {
	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	code_verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(),
		"http://example.org/callback", strconv.FormatInt(user.Id, 10), "openid profile offline_access",
		time.Now().Unix(), "code_value", int64(60*60*24), code_verifier, "07dfa90f")

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
			"iss": th.NewStrMatcher("example.org"),
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
			"iss": th.NewStrMatcher("example.org"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})
}

func TestTokenEndpointAuthorizationCodeInvalidRequest(t *testing.T) {
	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(),
		"http://example.org/callback", strconv.FormatInt(user.Id, 10), "openid profile offline_access",
		time.Now().Unix(), "code_value", int64(60*60*24), "", "07dfa90f")

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

	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

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
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		map[string]th.Matcher{
			"iss": th.NewStrMatcher("example.org"),
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
			"iss": th.NewStrMatcher("example.org"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})
}

func TestTokenEndpointAuthorizationCodeWithoutOfflineAccess(t *testing.T) {
	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(),
		"http://example.org/callback", strconv.FormatInt(user.Id, 10), "openid profile",
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
			"refresh_token": th.NewAbsentMatcher(),
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
		},
		map[string]th.Matcher{
			"iss": th.NewStrMatcher("example.org"),
			"sub": th.NewStrMatcher("0"),
			"aud": th.NewStrMatcher("client_id_01"),
		})
}

func TestTokenEndpointAuthorizationCodeWithoutOpenID(t *testing.T) {
	te := NewTokenEndpoint()
	te.Support(grant.AuthorizationCode())

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient("client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType(grant.TypeAuthorizationCode)

	sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(),
		"http://example.org/callback", strconv.FormatInt(user.Id, 10), "profile offline_access",
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
			"expires_in":    th.NewInt64Matcher(60 * 60 * 24),
			"id_token":      th.NewAbsentMatcher(),
		},
		nil)
}
