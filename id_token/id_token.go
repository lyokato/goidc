package id_token

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jws"
	"github.com/lestrrat/go-jwx/jwt"
)

func Hash(alg jwa.SignatureAlgorithm, token string) (string, error) {
	algStr := string(alg)
	if strings.HasSuffix(algStr, "256") {
		data := sha256.Sum256([]byte(token))
		return base64.StdEncoding.EncodeToString(data[:16]), nil
	} else if strings.HasSuffix(algStr, "384") {
		data := sha512.Sum384([]byte(token))
		return base64.StdEncoding.EncodeToString(data[:24]), nil
	} else if strings.HasSuffix(algStr, "512") {
		data := sha512.Sum512([]byte(token))
		return base64.StdEncoding.EncodeToString(data[:32]), nil
	} else {
		return "", errors.New("unsupported signature algorithm")
	}
}

func Gen(alg jwa.SignatureAlgorithm, key interface{},
	issure, clientId, subject, nonce string,
	expiresIn, authTime int64) (string, error) {

	exp := time.Now().Unix() + expiresIn
	iat := time.Now().Unix()

	return rawGen(alg, key,
		issure, clientId, subject,
		nonce, exp, authTime, iat,
		"", "")
}

func GenForImplicit(alg jwa.SignatureAlgorithm, key interface{},
	issure, clientId, subject, nonce string,
	expiresIn, authTime int64, accessToken string) (string, error) {

	exp := time.Now().Unix() + expiresIn
	iat := time.Now().Unix()

	atHash, err := Hash(alg, accessToken)
	if err != nil {
		return "", err
	}
	return rawGen(alg, key, issure, clientId, subject, nonce, exp, authTime, iat, atHash, "")
}

func GenForHybrid(alg jwa.SignatureAlgorithm, key interface{},
	issure, clientId, subject, nonce string,
	expiresIn, authTime int64, accessToken, code string) (string, error) {

	exp := time.Now().Unix() + expiresIn
	iat := time.Now().Unix()
	atHash, err := Hash(alg, accessToken)
	if err != nil {
		return "", err
	}
	cHash, err := Hash(alg, code)
	if err != nil {
		return "", err
	}
	return rawGen(alg, key, issure, clientId, subject, nonce, exp, authTime, iat, atHash, cHash)
}

func rawGen(alg jwa.SignatureAlgorithm, key interface{},
	issure, clientId, subject, nonce string,
	expiredAt, authTime, issuedAt int64, atHash, cHash string) (string, error) {

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
	if atHash != "" {
		c.Set("at_hash", atHash)
	}
	if cHash != "" {
		c.Set("c_hash", cHash)
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
