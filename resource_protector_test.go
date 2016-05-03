package goidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		UserId   int64  `json:"user_id"`
	}{
		r.Header.Get("REMOTE_USER"),
		r.Header.Get("X_OAUTH_CLIENT_ID"),
		r.Header.Get("X_OAUTH_SCOPE"),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestResourceProtector(t *testing.T) {

	sdi := th.NewTestStore()
	user := sdi.CreateNewUser("user01", "pass01")
	client := sdi.CreateNewClient(user.Id, "client_id_01", "client_secret_01", "http://example.org/callback")
	code_verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	ai, _ := sdi.CreateOrUpdateAuthInfo(user.Id, client.Id(),
		"http://example.org/callback", strconv.FormatInt(user.Id, 10), "openid profile offline_access",
		"code_value", int64(60*60*24), code_verifier, "07dfa90f")
	token, _ := sdi.CreateAccessToken(ai, true)

	rp := NewResourceProtector("api.example.org")
	ts := httptest.NewServer(testProtectedResourceMiddleware(
		rp, sdi, http.HandlerFunc(testProtectedResourceHandler)))
	defer ts.Close()
	c := http.DefaultClient
	r, err := http.NewRequest("POST", ts.URL, nil)
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken()))
	if err != nil {
		t.Errorf("failed to build request: %s", err)
		return
	}
	resp, err := c.Do(r)
	if err != nil {
		t.Errorf("failed http request: %s", err)
		return
	}

	if resp.StatusCode != 200 {
		t.Errorf("Status code - expect:%d, got:%d", 200, resp.StatusCode)
	}
}
