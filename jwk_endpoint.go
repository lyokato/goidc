package goidc

import (
	"crypto/rsa"
	"net/http"

	"github.com/lyokato/goidc/crypto"
)

type JWKEndpoint struct {
	keys map[string]*rsa.PublicKey
}

func NewJWKEndpoint() *JWKEndpoint {
	return &JWKEndpoint{
		keys: make(map[string]*rsa.PublicKey, 0),
	}
}

func (e *JWKEndpoint) AddFromFile(kid, path string) {
	k, err := crypto.LoadPublicKeyFromFile(path)
	if err != nil {
		panic(err)
	}
	e.keys[kid] = k
}

func (e *JWKEndpoint) AddFromText(kid, pem string) {
	k, err := crypto.LoadPublicKeyFromText(pem)
	if err != nil {
		panic(err)
	}
	e.keys[kid] = k
}

func (e *JWKEndpoint) Handler() http.HandlerFunc {
	json, _ := crypto.PublicKeysJWK(e.keys)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(json)
	}
}
