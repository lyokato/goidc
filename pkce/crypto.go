package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"strings"
	"time"
)

func GenRandomCodeVerifier() string {
	rand.Seed(time.Now().UnixNano())
	var data [32]byte
	for i := 0; i < 32; i++ {
		data[i] = byte(rand.Intn(256))
	}
	return EncodeBase64WithoutPadding(data[:])
}

func EncodeBase64WithoutPadding(origin []byte) string {
	encoded := base64.StdEncoding.EncodeToString(origin)
	parts := strings.Split(encoded, "=")
	encoded = parts[0]
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	return encoded
}

func S256Encode(origin string) string {
	data := sha256.Sum256([]byte(origin))
	return EncodeBase64WithoutPadding(data[:])
}
