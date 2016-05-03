package log

import "testing"

func TestTokenEndpointLog(t *testing.T) {
	actual := TokenEndpointLog("authorization_code", InterfaceUnsupported, map[string]string{
		"method": "FoobarMethod",
	}, "foobar")
	expected := "[goidc.TokenEndpoint:authorization_code] <InterfaceUnsupported method='FoobarMethod'>: foobar"
	if actual != expected {
		t.Errorf("Log:\n - got: %v\n - want: %v\n", actual, expected)
	}
}
