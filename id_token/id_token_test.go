package id_token

import (
	"testing"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lyokato/goidc/crypto"
)

func TestHash(t *testing.T) {
	access_token := "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
	actual_hash, err := Hash(jwa.RS256, access_token)
	if err != nil {
		t.Error("failed to gen at_hash")
		return
	}
	expected_hash := "77QmUPtjPfzWtF2AnpK9RQ"
	if actual_hash == expected_hash {
		t.Errorf("Hash: - got: %v\n - want: %v\n", actual_hash, expected_hash)
	}
}

func TestIdToken(t *testing.T) {

	privkey, err := crypto.LoadPrivateKeyFromText(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCzFyUUfVGyMCbG7YIwgo4XdqEjhhgIZJ4Kr7VKwIc7F+x0DoBn
iO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMwewb5Rcku33r+2QCETRmQMw68
eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBHoqxJsRC0l1ybcs6o0QIDAQAB
AoGBAIICU1DEiQIqInxW/yPoIu61l9UKC3hMUs6/L4TMr18exvCZdm2y4lKfQ5rM
g3HMM4H8wjG24f3OrqS/yKBDj/nnNAWqbhCRF49wn3gp1s/zLSxnHkR1nGmGlr3O
0jb22hR4aw9TFr7uJIe5YuWKWBG47p/cns9iVGV8sXVtrdABAkEA4ZfSD5I3F+rw
BFdB4WwRx7/hgb4kwq3E5GX44AYBvlymPcbDwiXXfC+zhhaZQ+VqZiGH8ecNIB4F
S/IvgkuJMQJBAMs6u13KRs+uSdT9YQ4OTbSAjldgHQKIScc427p7ik+Kg6eNqo1/
RUyRIclFf2s8HmCn6+zfAAk+Z76ocNn7MaECQQCGfp0d624tNEQkUmFUo7l1/U/U
qigAaNkZ0jGuXeZsN5BlBDtxZF40C7xcFN0LPZtRiGwkLDwHCd7eiGUKqT4BAkBJ
2zFGd4Febj+EuQRxgD87DtEr7dD9H5x4WzB3R/hOyc7osHI/8/WySrgVlj0lMnbz
t3Lk5XH06gn33u0MOt6hAkB1Jf6crfjGnoVE2aGt9SApdZIClFjjzcmhTjtHJVTo
tpgdYZY2kFpD7Nv0TxlmCsXf4JL/+Vd7pFtUuZVdNpfy
-----END RSA PRIVATE KEY-----`)
	if err != nil {
		t.Error("failed to prepare private key")
		return
	}

	clientId := "001"
	userPPID := "001"
	nonce := "128dfa9b"

	/*
		auth_time := time.Now().Unix() - 60*1
		expiresIn := 60 * 60 * 24
		exp := time.Now().Unix() + int64(expiresIn)
		iat := time.Now().Unix()
	*/

	exp := 1461934922
	iat := 1461848522
	auth_time := 1461848462

	actual_idt, err := rawGen(jwa.RS256, privkey,
		"org.example", clientId, userPPID,
		nonce, int64(exp), int64(auth_time), int64(iat), "", "")
	if err != nil {
		t.Errorf("Failed to generate id_token: %v", err)
		return
	}

	expected_idt := `eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiMDAxIl0sImV4cCI6MTQ2MTkzNDkyMiwiaWF0IjoxNDYxODQ4NTIyLCJpc3MiOiJvcmcuZXhhbXBsZSIsInN1YiI6IjAwMSIsImF1dGhfdGltZSI6MTQ2MTg0ODQ2Miwibm9uY2UiOiIxMjhkZmE5YiJ9.Wnoe_HxqCw2rrsEkP9oUEMHu99JxoevOZncXdsi9sabrl_WDmASQG8mD7riPcKDB8uBE1U3sJ4C565JqatT0Yh77IZ-KXkc0yq94430OTotjePdjqsjnQkh_EWeOIeDvPy56k5rU-aP05ZX48uRo2uYP9AWL3qnPfkvYEb1Y770`
	if actual_idt != expected_idt {
		t.Errorf("IDToken:\n - got: %v\n - want: %v\n", actual_idt, expected_idt)
	}

}
