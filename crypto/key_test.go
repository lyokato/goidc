package crypto

import (
	"crypto/rsa"
	"testing"
)

func TestJWKPublicKey(t *testing.T) {
	pk, err := LoadPublicKeyFromText(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)
	if err != nil {
		t.Error("LoadPublicKeyFromText should not fail with public key")
	}

	jwkBody, err := PublicKeysJWK(map[string]*rsa.PublicKey{
		"my_key_version": pk,
	})
	if err != nil {
		t.Errorf("failed to convert jwk")
	}
	actual := string(jwkBody)
	expected := `{
    "keys": [
        {
            "e": "AQAB",
            "kid": "my_key_version",
            "kty": "RSA",
            "n": "sxclFH1RsjAmxu2CMIKOF3ahI4YYCGSeCq-1SsCHOxfsdA6AZ4juroVOh1cTD4m8UgyBkCB6MT_RyTxhdV5RLexDMHsG-UXJLt96_tkAhE0ZkDMOvHmVGanbYMtSRQhbBVHDMHFXH06l1NNFBHrx_URQR6KsSbEQtJdcm3LOqNE"
        }
    ]
}`
	if actual != expected {
		t.Errorf("JWK:\n - got: %v\n - want: %v\n", actual, expected)
	}
}

func TestLoadPublicKeyFromJWK(t *testing.T) {
	jwkString := `{
    "keys": [
        {
            "e": "AQAB",
            "kid": "my_key_version",
            "kty": "RSA",
            "n": "sxclFH1RsjAmxu2CMIKOF3ahI4YYCGSeCq-1SsCHOxfsdA6AZ4juroVOh1cTD4m8UgyBkCB6MT_RyTxhdV5RLexDMHsG-UXJLt96_tkAhE0ZkDMOvHmVGanbYMtSRQhbBVHDMHFXH06l1NNFBHrx_URQR6KsSbEQtJdcm3LOqNE"
        }
    ]
}`
	pk, err := LoadPublicKeyFromJWK(jwkString, "my_key_version")
	if err != nil {
		t.Error("LoadPublicKeyFromJWK should not fail")
	}
	expected_E := 65537
	if pk.E != expected_E {
		t.Errorf("JWK:\n - got: %v\n - want: %v\n", pk.E, expected_E)
	}
	expected_N := "125761562406782462307976315837545894753596483913155629630845400922907150365823375233335966135888915653473579854535859095871067725653279636082966210229051847528843249278196841298129937769379799128054212839147877967083771260968564646064234593247897648494467957173841524414818545360053846191075030561605257439441"
	if pk.N.String() != expected_N {
		t.Errorf("JWK:\n - got: %v\n - want: %v\n", pk.N.String(), expected_N)
	}
}

func TestLoadPrivateKey(t *testing.T) {

	_, err := LoadPrivateKeyFromText("INVALID_PEM")
	if err == nil {
		t.Error("LoadPrivateKeyFromText should fail")
	}

	_, err = LoadPrivateKeyFromFile("./test_priv.pem")
	if err != nil {
		t.Error("LoadPrivateKeyFromText failed to load test_priv.pem")
	}

	_, err = LoadPrivateKeyFromFile("./test_pub.pem")
	if err == nil {
		t.Error("LoadPrivateKeyFromText should fail with test_pub.pem")
	}

	_, err = LoadPrivateKeyFromText(`-----BEGIN RSA PRIVATE KEY-----
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
		t.Error("LoadPrivateKeyFromText failed to load PEM text")
	}

	_, err = LoadPrivateKeyFromText(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)
	if err == nil {
		t.Error("LoadPrivateKeyFromText should fail with public key")
	}

}

func TestLoadPublicKey(t *testing.T) {

	_, err := LoadPublicKeyFromText("INVALID_PEM")
	if err == nil {
		t.Error("LoadPublicKeyFromText should fail")
	}

	_, err = LoadPublicKeyFromFile("./test_pub.pem")
	if err != nil {
		t.Error("LoadPublicKeyFromText failed to load test_pub.pem")
	}

	_, err = LoadPublicKeyFromFile("./test_priv.pem")
	if err == nil {
		t.Error("LoadPublicKeyFromText should fail with test_priv.pem")
	}

	_, err = LoadPublicKeyFromText(`-----BEGIN RSA PRIVATE KEY-----
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
	if err == nil {
		t.Error("LoadPublicKeyFromText should fail with private key")
	}

	_, err = LoadPublicKeyFromText(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)
	if err != nil {
		t.Error("LoadPublicKeyFromText should not fail with public key")
	}

}
