package test_helper

type (
	TestAuthSession struct {
		authId       int64
		redirectUri  string
		authTime     int64
		code         string
		expiresIn    int64
		codeVerifier string
		nonce        string

		Enabled bool
	}
)

func (s *TestAuthSession) GetAuthId() int64 {
	return s.authId
}

func (s *TestAuthSession) GetAuthTime() int64 {
	return s.authTime
}

func (s *TestAuthSession) GetAuthorizedAt() int64 {
	// FIXME
	return s.authTime
}

func (s *TestAuthSession) GetIdTokenExpiresIn() int64 {
	return int64(60 * 60 * 24 * 7)
}

func (s *TestAuthSession) GetCode() string {
	return s.code
}

func (s *TestAuthSession) GetExpiresIn() int64 {
	return s.expiresIn
}

func (s *TestAuthSession) GetCodeVerifier() string {
	return s.codeVerifier
}

func (s *TestAuthSession) GetRedirectURI() string {
	return s.redirectUri
}

func (s *TestAuthSession) GetNonce() string {
	return s.nonce
}
