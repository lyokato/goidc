package test_helper

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/lyokato/goidc/crypto"
)

func GetFormValueRequestWithJSONResponse(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders map[string]Matcher) map[string]interface{} {
	return FormValueRequestWithJSONResponse(t, server, "GET", values, requestHeaders, code, responseHeaders)
}

func ProtectedResourceSuccessTest(t *testing.T, server *httptest.Server, method string, values, requestHeaders map[string]string, code int, responseHeaders, responseValues map[string]Matcher) {
	result := FormValueRequestWithJSONResponse(t, server, method, values, requestHeaders, code, responseHeaders)
	for k, matcher := range responseValues {
		rv, exists := result[k]
		if matcher.RequireAbsent() {
			if exists {
				t.Errorf("Response:%s should be absent: ", k)
				continue
			}
		} else {
			if !exists {
				t.Errorf("Response:%s not found: ", k)
				continue
			}
			if !matcher.Match(rv) {
				t.Errorf("Response:%s isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
			}
		}
	}
}

func ProtectedResourceErrorTest(t *testing.T, server *httptest.Server, method string, values, requestHeaders map[string]string, code int, responseHeaders map[string]Matcher) {

	params := url.Values{}
	for k, v := range values {
		params.Add(k, v)
	}

	var reader io.Reader
	if method == "POST" {
		reader = strings.NewReader(params.Encode())
	}

	url := server.URL
	if method == "GET" {
		url = server.URL + "?" + params.Encode()
	}

	r, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Errorf("failed to build request: %v", err)
		return
	}

	if requestHeaders != nil {
		for k, v := range requestHeaders {
			r.Header.Set(k, v)
		}
	}

	c := http.DefaultClient
	resp, err := c.Do(r)
	if err != nil {
		t.Errorf("failed http request: %v", err)
		return
	}

	if resp.StatusCode != code {
		t.Errorf("Status code - expect:%d, got:%d", code, resp.StatusCode)
	}

	fmt.Printf("%v\n", resp.Header)
	if responseHeaders != nil {
		for k, matcher := range responseHeaders {
			rv := resp.Header.Get(k)
			if matcher.RequireAbsent() {
				if rv != "" {
					t.Errorf("ResponseHeader:%s should be absent: ", k)
					continue
				}
			} else {
				if rv == "" {
					t.Errorf("ResponseHeader:%s not found: ", k)
					continue
				}
				if !matcher.Match(rv) {
					t.Errorf("ResponseHeader:%s isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
				}
			}
		}
	}

}

func TokenEndpointSuccessTest(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders, responseValues, idTokenValues map[string]Matcher) {

	result := PostFormValueRequestWithJSONResponse(t, server, values, requestHeaders, code, responseHeaders)

	for k, matcher := range responseValues {
		rv, exists := result[k]
		if matcher.RequireAbsent() {
			if exists {
				t.Errorf("Response:%s should be absent: ", k)
				continue
			}
		} else {
			if !exists {
				t.Errorf("Response:%s not found: ", k)
				continue
			}
			if !matcher.Match(rv) {
				t.Errorf("Response:%s isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
			}
		}
	}

	if idTokenValues == nil {
		return
	}

	idti, exists := result["id_token"]
	if !exists {
		t.Error("'id_token' not found")
		return
	}

	idts, ok := idti.(string)
	if !ok {
		t.Error("'id_token' isn't string")
		return
	}

	idt, err := jwt.Parse(idts, func(token *jwt.Token) (interface{}, error) {
		return crypto.LoadPublicKeyFromText(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)
	})
	if err != nil {
		t.Errorf("failed to parse token %s", err)
		return
	}

	for k, matcher := range idTokenValues {
		rv, exists := idt.Claims[k]
		if !exists {
			t.Errorf("IDToken:Calim:%s not found: ", k)
			continue
		}
		if !matcher.Match(rv) {
			t.Errorf("IDToken:Claim:%s isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
		}
	}

}

func TokenEndpointErrorTest(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders, errors map[string]Matcher) {
	result := PostFormValueRequestWithJSONResponse(t, server, values, requestHeaders, code, responseHeaders)
	for k, matcher := range errors {
		rv, exists := result[k]
		if !exists {
			t.Errorf("ErrorResponse:%s not found: ", k)
			continue
		}
		if !matcher.Match(rv) {
			t.Errorf("ErrorResponse:%s isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
		}
	}
}

func PostFormValueRequestWithJSONResponse(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders map[string]Matcher) map[string]interface{} {
	return FormValueRequestWithJSONResponse(t, server, "POST", values, requestHeaders, code, responseHeaders)
}

func FormValueRequestWithJSONResponse(t *testing.T, server *httptest.Server, method string, values, requestHeaders map[string]string,
	code int, responseHeaders map[string]Matcher) map[string]interface{} {

	params := url.Values{}
	for k, v := range values {
		params.Add(k, v)
	}

	var reader io.Reader
	if method == "POST" {
		reader = strings.NewReader(params.Encode())
	}

	url := server.URL
	if method == "GET" {
		url = server.URL + "?" + params.Encode()
	}

	r, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Errorf("failed to build request: %v", err)
		return nil
	}

	if requestHeaders != nil {
		for k, v := range requestHeaders {
			r.Header.Set(k, v)
		}
	}

	c := http.DefaultClient
	resp, err := c.Do(r)
	if err != nil {
		t.Errorf("failed http request: %v", err)
		return nil
	}

	if resp.StatusCode != code {
		t.Errorf("Status code - expect:%d, got:%d", code, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	if responseHeaders != nil {
		for k, v := range responseHeaders {
			if !v.Match(resp.Header.Get(k)) {
				t.Errorf("ResponseHeader<%s> isn't match", k)
			}
		}
	}

	var f interface{}
	json.Unmarshal(body, &f)
	return f.(map[string]interface{})
}
