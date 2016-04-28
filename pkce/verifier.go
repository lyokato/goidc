package pkce

import "fmt"

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

type (
	Verifier interface {
		Verify(challenge, verifier string) bool
	}
	plainVerifier struct{}
	s256Verifier  struct{}
)

var plain = &plainVerifier{}
var s256 = &s256Verifier{}

func FindVerifierByMethod(method string) (Verifier, error) {
	switch method {
	case CodeChallengeMethodPlain:
		return plain, nil
	case CodeChallengeMethodS256:
		return s256, nil
	default:
		return nil, fmt.Errorf("unknown code_challange_method: %s", method)
	}
}

func (v *plainVerifier) Verify(challenge, verifier string) bool {
	return challenge == verifier
}

func (v *s256Verifier) Verify(challenge, verifier string) bool {
	return S256Encode(verifier) == challenge
}
