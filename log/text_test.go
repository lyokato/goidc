package log

import "testing"

func TestTokenEndpointLog(t *testing.T) {
	actual := TokenEndpointLog("authorization_code", InterfaceUnsupported, map[string]string{
		"method": "FoobarMethod",
	}, "foobar")
	expected := "[goidc:token_endpoint:\x1b[1;34mauthorization_code\x1b[m:\x1b[36minterface_unsupported\x1b[m] foobar \x1b[1;31m{\"method\":\"FoobarMethod\"}\x1b[m"
	if actual != expected {
		t.Errorf("Log:\n - got: %v\n - want: %v\n", actual, expected)
	}
}
