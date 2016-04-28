package pkce

import "testing"

func TestEncodeBase64WithoutPadding(t *testing.T) {
	data := []byte{116, 24, 223, 180, 151,
		153, 224, 37, 79, 250, 96, 125, 216, 173,
		187, 186, 22, 212, 37, 77, 105, 214, 191,
		240, 91, 88, 5, 88, 83, 132, 141, 121}
	actual_encoded := EncodeBase64WithoutPadding(data)
	expected_encoded := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if actual_encoded != expected_encoded {
		t.Errorf("EncodeBase64WithoutPadding:\n - got: %v\n - want: %v\n", actual_encoded, expected_encoded)
	}
}

func TestEncodePKCES256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	actual_encoded := S256Encode(verifier)
	expected_encoded := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if actual_encoded != expected_encoded {
		t.Errorf("S64Encode:\n - got: %v\n - want: %v\n", actual_encoded, expected_encoded)
	}
}
