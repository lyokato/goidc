package basic_auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestToken(t *testing.T) {
	actual := Token("userid", "password")
	expected := "dXNlcmlkOnBhc3N3b3Jk"
	if actual != expected {
		t.Errorf("Token: \n - got: %v\n - want: %v\n", actual, expected)
	}
}

func TestHeader(t *testing.T) {
	actual := Header("userid", "password")
	expected := "Basic dXNlcmlkOnBhc3N3b3Jk"
	if actual != expected {
		t.Errorf("Header: \n - got: %v\n - want: %v\n", actual, expected)
	}
}

func TestParseHeader(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.org/", nil)
	if err != nil {
		t.Errorf("failed to create http request: %s", err)
		return
	}
	r.Header.Set("Authorization", "Basic dXNlcmlkOnBhc3N3b3Jk")

	cid, sec, exists := FindClientCredential(r)
	if !exists {
		t.Error("client_id and client_secret not found in request")
		return
	}

	expected_cid := "userid"
	expected_sec := "password"
	if cid != expected_cid {
		t.Errorf("client_id:\n - got: %v\n - want: %v", cid, expected_cid)
	}
	if sec != expected_sec {
		t.Errorf("client_secret:\n - got: %v\n - want: %v", sec, expected_sec)
	}
}

func TestParseInvalidValueHeader(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.org/", nil)
	if err != nil {
		t.Errorf("failed to create http request: %s", err)
		return
	}
	r.Header.Set("Authorization", "Basic bdXNlcmlkOnBhc3N3b3Jk")

	_, _, exists := FindClientCredential(r)
	if exists {
		t.Error("client_id and client_secret not found in request")
		return
	}
}

func TestParseInvalidTypeHeader(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.org/", nil)
	if err != nil {
		t.Errorf("failed to create http request: %s", err)
		return
	}
	r.Header.Set("Authorization", "Bearer dXNlcmlkOnBhc3N3b3Jk")

	_, _, exists := FindClientCredential(r)
	if exists {
		t.Error("client_id and client_secret not found in request")
		return
	}

}

func TestParseQuery(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.org/?client_id=userid&client_secret=password", nil)
	if err != nil {
		t.Errorf("failed to create http request: %s", err)
		return
	}

	cid, sec, exists := FindClientCredential(r)
	if !exists {
		t.Error("client_id and client_secret not found in request")
		return
	}

	expected_cid := "userid"
	expected_sec := "password"
	if cid != expected_cid {
		t.Errorf("client_id:\n - got: %v\n - want: %v", cid, expected_cid)
	}
	if sec != expected_sec {
		t.Errorf("client_secret:\n - got: %v\n - want: %v", sec, expected_sec)
	}
}

func TestParsePostBody(t *testing.T) {

	v := url.Values{}
	v.Add("client_id", "userid")
	v.Add("client_secret", "password")
	r, err := http.NewRequest("POST", "http://example.org/", strings.NewReader(v.Encode()))
	if err != nil {
		t.Errorf("failed to create http request: %s", err)
		return
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	cid, sec, exists := FindClientCredential(r)
	if !exists {
		t.Error("client_id and client_secret not found in request")
		return
	}

	expected_cid := "userid"
	expected_sec := "password"
	if cid != expected_cid {
		t.Errorf("client_id:\n - got: %v\n - want: %v", cid, expected_cid)
	}
	if sec != expected_sec {
		t.Errorf("client_secret:\n - got: %v\n - want: %v", sec, expected_sec)
	}
}
