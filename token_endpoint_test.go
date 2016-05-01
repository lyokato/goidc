package goidc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lyokato/goidc/basic_auth"
	"github.com/lyokato/goidc/grant"
	oer "github.com/lyokato/goidc/oauth_error"
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

	te.SetErrorURIBuilder(func(errorType oer.OAuthErrorType) string {
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
