package goidc

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWKEndpoint(t *testing.T) {
	je := NewJWKEndpoint()
	je.AddFromText("my_key_id", `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzFyUUfVGyMCbG7YIwgo4XdqEj
hhgIZJ4Kr7VKwIc7F+x0DoBniO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMw
ewb5Rcku33r+2QCETRmQMw68eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBH
oqxJsRC0l1ybcs6o0QIDAQAB
-----END PUBLIC KEY-----`)

	ts := httptest.NewServer(je.Handler())
	defer ts.Close()

	r, _ := http.NewRequest("GET", ts.URL, nil)
	resp, _ := http.DefaultClient.Do(r)

	if resp.StatusCode != 200 {
		t.Errorf("Status code\n - got: %d\n, - want: %d\n", resp.StatusCode, 200)
		return
	}

	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	actual := string(body)
	expected := `{
    "keys": [
        {
            "e": "AQAB",
            "kid": "my_key_id",
            "kty": "RSA",
            "n": "sxclFH1RsjAmxu2CMIKOF3ahI4YYCGSeCq-1SsCHOxfsdA6AZ4juroVOh1cTD4m8UgyBkCB6MT_RyTxhdV5RLexDMHsG-UXJLt96_tkAhE0ZkDMOvHmVGanbYMtSRQhbBVHDMHFXH06l1NNFBHrx_URQR6KsSbEQtJdcm3LOqNE"
        }
    ]
}`
	if actual != expected {
		t.Errorf("kti\n - got: %s\n, - want: %s\n", actual, expected)
	}
}
