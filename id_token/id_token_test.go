package id_token

import (
	"testing"

	"github.com/lyokato/goidc/crypto"
)

func TestHash(t *testing.T) {
	access_token := "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
	actual_hash, err := Hash("RS256", access_token)
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

	actual_idt, err := rawGen("RS256", privkey, "my_key_id",
		"org.example", clientId, userPPID,
		nonce, int64(exp), int64(auth_time), int64(iat), "", "")
	if err != nil {
		t.Errorf("Failed to generate id_token: %v", err)
		return
	}

	expected_idt := `eyJhbGciOiJSUzI1NiIsImtpZCI6Im15X2tleV9pZCIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIwMDEiLCJhdXRoX3RpbWUiOjE0NjE4NDg0NjIsImV4cCI6MTQ2MTkzNDkyMiwiaWF0IjoxNDYxODQ4NTIyLCJpc3MiOiJvcmcuZXhhbXBsZSIsIm5vbmNlIjoiMTI4ZGZhOWIiLCJzdWIiOiIwMDEifQ.hWd3AWBfSRd2U4i5KTNg8ESkJeWT9bEI5B5xrICprOMe2R3EVcCSWoVOsLXHGDTQCDb3kxPIdfqiGvBMrh-_aekp7HzyG9oZmcKhFKRgZvYTeSoPtfPvLSTNjw39ySdJY1i9gAMXVC6R52hIwQ88nryWOcRG9GyS324LvMoBfr8`
	if actual_idt != expected_idt {
		t.Errorf("IDToken:\n - got: %v\n - want: %v\n", actual_idt, expected_idt)
	}

}
