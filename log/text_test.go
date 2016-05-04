package log

import "testing"

func TestTokenEndpointLog(t *testing.T) {
	actual := TokenEndpointLog("authorization_code", InterfaceUnsupported, map[string]string{
		"method": "FoobarMethod",
	}, "foobar")
	expected := "[goidc.TokenEndpoint:\x1b[35mauthorization_code\x1b[m] <\x1b[33minterface_unsupported\x1b[m method=\"FoobarMethod\">: foobar"
	if actual != expected {
		t.Errorf("Log:\n - got: %v\n - want: %v\n", actual, expected)
	}
}
