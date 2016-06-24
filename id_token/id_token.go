package id_token

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func Hash(alg string, token string) (string, error) {
	if strings.HasSuffix(alg, "256") {
		data := sha256.Sum256([]byte(token))
		return base64.StdEncoding.EncodeToString(data[:16]), nil
	} else if strings.HasSuffix(alg, "384") {
		data := sha512.Sum384([]byte(token))
		return base64.StdEncoding.EncodeToString(data[:24]), nil
	} else if strings.HasSuffix(alg, "512") {
		data := sha512.Sum512([]byte(token))
		return base64.StdEncoding.EncodeToString(data[:32]), nil
	} else {
		return "", errors.New("unsupported signature algorithm")
	}
}

func Gen(alg string, key interface{}, keyId,
	issuer, clientId, subject, nonce string,
	expiresIn, authTime int64, now time.Time) (string, error) {

	exp := now.Unix() + expiresIn
	iat := now.Unix()

	return rawGen(alg, key, keyId,
		issuer, clientId, subject,
		nonce, exp, authTime, iat,
		"", "")
}

func GenForImplicit(alg string, key interface{}, keyId,
	issuer, clientId, subject, nonce string,
	expiresIn, authTime int64, accessToken string, now time.Time) (string, error) {

	exp := now.Unix() + expiresIn
	iat := now.Unix()

	atHash := ""
	var err error
	if accessToken != "" {
		atHash, err = Hash(alg, accessToken)
		if err != nil {
			return "", err
		}
	}
	return rawGen(alg, key, keyId,
		issuer, clientId, subject,
		nonce, exp, authTime, iat, atHash, "")
}

func GenForHybrid(alg string, key interface{}, keyId,
	issuer, clientId, subject, nonce string,
	expiresIn, authTime int64, accessToken, code string, now time.Time) (string, error) {

	exp := now.Unix() + expiresIn
	iat := now.Unix()
	atHash := ""
	var err error
	if accessToken != "" {
		atHash, err = Hash(alg, accessToken)
		if err != nil {
			return "", err
		}
	}
	cHash, err := Hash(alg, code)
	if err != nil {
		return "", err
	}
	return rawGen(alg, key, keyId,
		issuer, clientId, subject,
		nonce, exp, authTime, iat, atHash, cHash)
}

func rawGen(alg string, key interface{}, keyId,
	issuer, clientId, subject, nonce string,
	expiredAt, authTime, issuedAt int64, atHash, cHash string) (string, error) {

	meth := jwt.GetSigningMethod(alg)
	if meth == nil {
		return "", fmt.Errorf("unknown jwt signing algorithm: %s", alg)
	}

	token := jwt.New(meth)
	claims := token.Claims.(jwt.MapClaims)
	claims["iss"] = issuer
	claims["aud"] = clientId
	claims["sub"] = subject
	claims["exp"] = expiredAt
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if issuedAt >= 0 {
		claims["iat"] = issuedAt
	}
	if authTime >= 0 {
		claims["auth_time"] = authTime
	}
	if atHash != "" {
		claims["at_hash"] = atHash
	}
	if cHash != "" {
		claims["c_hash"] = cHash
	}
	if keyId != "" {
		token.Header["kid"] = keyId
	}
	return token.SignedString(key)
}
