package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/lestrrat/go-jwx/jwk"
)

func PublicKeysJWK(keys map[string]*rsa.PublicKey) ([]byte, error) {
	set := &jwk.Set{}
	for kid, key := range keys {
		rk, err := jwk.NewRsaPublicKey(key)
		if err != nil {
			return nil, err
		}
		rk.KeyID = kid
		set.Keys = append(set.Keys, rk)
	}
	body, err := json.MarshalIndent(set, "", "    ")
	if err != nil {
		return nil, err
	}
	return body, nil
}

func LoadPublicKeyFromJWK(jwkString, kid string) (*rsa.PublicKey, error) {
	set, err := jwk.ParseString(jwkString)
	if err != nil {
		return nil, err
	}
	keys := set.LookupKeyID(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("indicated key id not found")
	} else {
		pk, ok := keys[0].(*jwk.RsaPublicKey)
		if !ok {
			return nil, errors.New("indicated key is not a public key")
		}
		return pk.PublicKey()
	}
}

func LoadPublicKeyFromFile(pemPath string) (*rsa.PublicKey, error) {
	pem, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %s", err)
	}
	return LoadPublicKeyFromData(pem)
}

func LoadPublicKeyFromText(data string) (*rsa.PublicKey, error) {
	return LoadPublicKeyFromData([]byte(data))
}

func LoadPublicKeyFromData(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block isn't a RSA PRIVATE KEY")
	}
	pubkeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key can't be decoded: %s", err)
	}
	pubkey, ok := pubkeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("couldn't convert to a RSA public key")
	}
	return pubkey, nil
}

func LoadPrivateKeyFromFile(pemPath string) (*rsa.PrivateKey, error) {
	pem, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %s", err)
	}
	return LoadPrivateKeyFromData(pem)
}

func LoadPrivateKeyFromText(data string) (*rsa.PrivateKey, error) {
	return LoadPrivateKeyFromData([]byte(data))
}

func LoadPrivateKeyFromData(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block isn't a RSA PRIVATE KEY")
	}
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key can't be decoded: %s", err)
	}
	return privkey, nil
}
