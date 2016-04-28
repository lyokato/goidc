package goidc

import (
	"net/http"
	"testing"
)

func TestErrorBasic(t *testing.T) {
	oe := NewOAuthError(ErrInvalidRequest, "this client_id is disabled", "http://example.org/path/to/error/document")
	actual_error := oe.Error()
	expected_error := "invalid_request: this client_id is disabled"
	if actual_error != expected_error {
		t.Errorf("Error:\n - got: %v\n - want: %v\n", actual_error, expected_error)
	}

	actual_header := oe.Header("example.org")
	expected_header := "Bearer realm=\"example.org\", error=\"invalid_request\", error_description=\"this client_id is disabled\", error_uri=\"http://example.org/path/to/error/document\""
	if actual_header != expected_header {
		t.Errorf("Header:\n - got: %v\n - want: %v\n", actual_header, expected_header)
	}

	actual_code := oe.StatusCode()
	expected_code := http.StatusBadRequest
	if actual_code != expected_code {
		t.Errorf("Header:\n - got: %d\n - want: %d\n", actual_code, expected_code)
	}

	actual_json := string(oe.JSON())
	expected_json := "{\"error\":\"invalid_request\",\"error_description\":\"this client_id is disabled\",\"uri\":\"http://example.org/path/to/error/document\"}"
	if actual_json != expected_json {
		t.Errorf("Header:\n - got: %v\n - want: %v\n", actual_json, expected_json)
	}
}
