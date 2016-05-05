package goidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sd "github.com/lyokato/goidc/service_data"
	th "github.com/lyokato/goidc/test_helper"
)

func testProtectedResourceMiddleware(rp *ResourceProtector,
	sdi sd.ServiceDataInterface, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rp.Validate(w, r, sdi) {
			next.ServeHTTP(w, r)
		}
	})
}

func testProtectedResourceHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := json.Marshal(struct {
		ClientId string `json:"client_id"`
		Scope    string `json:"scope"`
		UserId   string `json:"user_id"`
	}{
		r.Header.Get("X-OAUTH-CLIENT-ID"),
		r.Header.Get("X-OAUTH-SCOPE"),
		r.Header.Get("REMOTE_USER"),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestResourceProtector(t *testing.T) {

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	ai, _ := sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(), "openid profile offline_access", nil)
	token, _ := sdi.CreateAccessToken(ai, true)

	rp := NewResourceProtector("api.example.org")
	ts := httptest.NewServer(testProtectedResourceMiddleware(
		rp, sdi, http.HandlerFunc(testProtectedResourceHandler)))
	defer ts.Close()

	th.ProtectedResourceSuccessTest(t, ts, "POST",
		map[string]string{},
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
			"Authorization": fmt.Sprintf("Bearer %s", token.AccessToken()),
		},
		200,
		map[string]th.Matcher{
			"Content-Type": th.NewStrMatcher("application/json"),
		},
		map[string]th.Matcher{
			"client_id": th.NewStrMatcher("client_id_01"),
			"scope":     th.NewStrMatcher("openid profile offline_access"),
			"user_id":   th.NewStrMatcher("0"),
		})

	th.ProtectedResourceErrorTest(t, ts, "POST",
		map[string]string{},
		map[string]string{},
		400,
		map[string]th.Matcher{
			"WWW-Authenticate": th.NewStrMatcher("Bearer realm=\"api.example.org\", error=\"invalid_request\""),
		})

	th.ProtectedResourceErrorTest(t, ts, "POST",
		map[string]string{},
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", "invalid token"),
		},
		401,
		map[string]th.Matcher{
			"WWW-Authenticate": th.NewStrMatcher("Bearer realm=\"api.example.org\", error=\"invalid_token\""),
		})
}