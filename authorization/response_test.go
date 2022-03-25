package authorization

import (
	"testing"
)

func TestConnector(t *testing.T) {
	testConnector(t, ParamTypeQuery, "https://example.com", "?")
	testConnector(t, ParamTypeQuery, "https://example.com?foo=bar", "&")
	testConnector(t, ParamTypeFragment, "https://example.com", "#")
	testConnector(t, ParamTypeFragment, "https://example.com#foo=bar", "&")
}

func testConnector(t *testing.T, p ResponseParamType, uri, expected string) {
	c := &RedirectResponseHandler{w: nil, r: nil, pt: p}
	actual := c.pt.Connector(uri)

	if actual != expected {
		t.Errorf("Connector for [%s]\n - got: %v\n - want: %v\n", uri, actual, expected)
	}
}
