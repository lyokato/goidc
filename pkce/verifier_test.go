package pkce

import "testing"

func TestPlainVerifier(t *testing.T) {

	verifier := "foobar"
	method := "plain"
	challenge := "foobar"
	invalid_challenge := "barbuz"

	v, err := FindVerifierByMethod(method)
	if err != nil {
		t.Errorf("couldn't find proper verifier: %s", err)
		return
	}

	if !v.Verify(challenge, verifier) {
		t.Error("couldn't verify")
	}

	if v.Verify(invalid_challenge, verifier) {
		t.Error("Verification should fail")
	}

}

func TestUnknownVerifier(t *testing.T) {

	method := "unknown"

	_, err := FindVerifierByMethod(method)
	if err == nil {
		t.Errorf("couldn't find proper verifier: %s", err)
	}
}

func TestS256Verifier(t *testing.T) {

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	method := "S256"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	invalid_challenge := "A9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	v, err := FindVerifierByMethod(method)
	if err != nil {
		t.Errorf("couldn't find proper verifier: %s", err)
		return
	}

	if !v.Verify(challenge, verifier) {
		t.Error("couldn't verify")
	}

	if v.Verify(invalid_challenge, verifier) {
		t.Error("Verification should fail")
	}

}
