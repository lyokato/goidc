package test_helper

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

type (
	Matcher interface {
		Match(v interface{}) bool
		WantValue() string
	}
	Int64Matcher struct {
		value int64
	}
	Int64RangeMatcher struct {
		from int64
		to   int64
	}
	StrMatcher struct {
		value string
	}
	RegexMatcher struct {
		origin string
		value  *regexp.Regexp
	}
)

func NewInt64Matcher(v int64) *Int64Matcher {
	return &Int64Matcher{v}
}

func NewInt64RangeMatcher(from, to int64) *Int64RangeMatcher {
	return &Int64RangeMatcher{from, to}
}

func (m *Int64Matcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Float64 {
		return false
	}
	int_value, _ := v.(int64)
	return m.value == int_value
}

func (m *Int64Matcher) WantValue() string {
	return fmt.Sprintf("%d", m.value)
}

func (m *Int64RangeMatcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Float64 {
		return false
	}
	int_value, _ := v.(int64)
	return m.from <= int_value && m.to >= int_value
}

func (m *Int64RangeMatcher) WantValue() string {
	return fmt.Sprintf("%d ~ %d", m.from, m.to)
}

func NewStrMatcher(v string) *StrMatcher {
	return &StrMatcher{v}
}

func (m *StrMatcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.String {
		return false
	}
	str, _ := v.(string)
	return m.value == str
}

func (m *StrMatcher) WantValue() string {
	return m.value
}

func NewRegexMatcher(v string) *RegexMatcher {
	return &RegexMatcher{v, regexp.MustCompile(v)}
}

func (m *RegexMatcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.String {
		return false
	}
	str, _ := v.(string)
	return m.value.MatchString(str)
}

func (m *RegexMatcher) WantValue() string {
	return m.origin
}

func GetFormValueRequestWithJSONResponse(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders map[string]Matcher) map[string]interface{} {
	return FormValueRequestWithJSONResponse(t, server, "GET", values, requestHeaders, code, responseHeaders)
}

func TokenEndpointSuccessTest(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders, responseValues, idTokenValues map[string]Matcher) {

	result := PostFormValueRequestWithJSONResponse(t, server, values, requestHeaders, code, responseHeaders)

	for k, matcher := range responseValues {
		rv, exists := result[k]
		if !exists {
			t.Errorf("Response<%s> not found: ", k)
			continue
		}
		if !matcher.Match(rv) {
			t.Errorf("Response<%s> isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
		}
	}
}

func TokenEndpointErrorTest(t *testing.T, server *httptest.Server, values, requestHeaders map[string]string,
	code int, responseHeaders, errors map[string]Matcher) {
	result := PostFormValueRequestWithJSONResponse(t, server, values, requestHeaders, code, responseHeaders)
	for k, matcher := range errors {
		rv, exists := result[k]
		if !exists {
			t.Errorf("ErrorResponse<%s> not found: ", k)
			continue
		}
		if !matcher.Match(rv) {
			t.Errorf("ErrorResponse<%s> isn't match\n - got: %v\n - want: %v\n", k, rv, matcher.WantValue())
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
