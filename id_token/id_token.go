package id_token

import (
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
)

func Gen(alg jwa.SignatureAlgorithm, key *rsa.PrivateKey,
	issure, clientId, subject, nonce string,
	expiresIn, authTime int64) (string, error) {

	exp := time.Now().Unix() + expiresIn
	iat := time.Now().Unix()

	return rawGen(alg, key, issure, clientId, subject, nonce, exp, authTime, iat)
}

func rawGen(alg jwa.SignatureAlgorithm, key *rsa.PrivateKey,
	issure, clientId, subject, nonce string,
	expiredAt, authTime, issuedAt int64) (string, error) {

	c := jwt.NewClaimSet()
	c.Set("iss", issure)
	c.Set("aud", clientId)
	c.Set("sub", subject)
	c.Set("exp", expiredAt)
	if nonce != "" {
		c.Set("nonce", nonce)
	}
	if issuedAt >= 0 {
		c.Set("iat", issuedAt)
	}
	if authTime >= 0 {
		c.Set("auth_time", authTime)
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	token, err := jws.Sign(buf, alg, key)
	if err != nil {
		return "", err
	}
	return string(token), nil
}
