package goidc

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lyokato/goidc/authorizer"
	"github.com/lyokato/goidc/grant"
	th "github.com/lyokato/goidc/test_helper"
)

func TestTokenEndpointClientAssertion(t *testing.T) {

	te := NewTokenEndpoint("api.example.org")
	te.Support(grant.AuthorizationCode())
	te.Support(grant.Password())
	te.Support(grant.ClientCredentials())
	te.AcceptClientAssertion(true)

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	client.AllowToUseGrantType("authorization_code")

	sdi.CreateOrUpdateAuthInfo(user.Id, client.GetId(), "openid profile offline_access",
		&authorizer.Session{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  "",
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
			AuthTime:      time.Now().Unix(),
		})

	key := client.GetAssertionKey("", "")
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24

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

	// with valid nbf
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24
	token.Claims["nbf"] = time.Now().Unix() - 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	sdi.CreateOrUpdateAuthInfo(user.Id, client.GetId(), "openid profile offline_access",
		&authorizer.Session{
			RedirectURI:   "http://example.org/callback",
			Code:          "code_value",
			CodeVerifier:  "",
			CodeExpiresIn: int64(60 * 60 * 24),
			Nonce:         "07dfa90f",
			AuthTime:      time.Now().Unix(),
		})

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

	// aud not found
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	//token.Claims["aud"] = "http://unknown.example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("'aud' parameter not found in assertion"),
		})

	// INVALID aud
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://unknown.example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_grant"),
			"error_description": th.NewStrMatcher("invalid 'aud' parameter 'http://unknown.example.org/' in assertion"),
		})

	// exp NOT FOUND
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("'exp' parameter not found in assertion"),
		})

	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() - 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_grant"),
			"error_description": th.NewStrMatcher("assertion expired"),
		})

	// include nbf, but it's future
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["nbf"] = time.Now().Unix() + 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_grant"),
			"error_description": th.NewStrMatcher("assertion not valid yet"),
		})

	// sub not found
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://unknown.example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	//token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error":             th.NewStrMatcher("invalid_request"),
			"error_description": th.NewStrMatcher("'sub' parameter not found in assertion"),
		})

	// invalid sub
	key = client.GetAssertionKey("", "")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://unknown.example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "unknown_client_id"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error": th.NewStrMatcher("invalid_client"),
		})

	// invalid key
	key = []byte("foobarbuz")
	token = jwt.New(jwt.SigningMethodHS256)
	token.Claims["aud"] = "http://example.org/"
	token.Claims["iss"] = "http://client.example.org/"
	token.Claims["sub"] = "client_id_01"
	token.Claims["exp"] = time.Now().Unix() + 60*60*24

	assertion, err = token.SignedString(key)
	if err != nil {
		t.Errorf("failed to sign jwt, %s", err)
	}

	th.TokenEndpointErrorTest(t, ts,
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
		400,
		map[string]th.Matcher{
			"Content-Type":  th.NewStrMatcher("application/json; charset=UTF-8"),
			"Pragma":        th.NewStrMatcher("no-cache"),
			"Cache-Control": th.NewStrMatcher("no-store"),
		},
		map[string]th.Matcher{
			"error": th.NewStrMatcher("invalid_client"),
		})
}
