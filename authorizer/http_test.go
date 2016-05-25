package authorizer

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParser(t *testing.T) {

	v := url.Values{}

	v.Add("response_type", "code")
	v.Add("client_id", "abcdef")
	v.Add("redirect_uri", "http://example.org/callback")
	v.Add("scope", "openid profile")

	url := "http://example.org?" + v.Encode()

	hr, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Errorf("failed to build http request: %s", err)
	}

	ar, err := ConvertHTTPRequest(hr)
	if err != nil {
		t.Errorf("found error on request: %s", err)
		return
	}

	if ar.Flow.Type != FlowTypeAuthorizationCode {
		t.Error("flow type should be basic")
	}
}
