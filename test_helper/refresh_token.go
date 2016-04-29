package test_helper

type (
	TestRefreshToken struct {
		authId    int64
		token     string
		expiresIn int64
		createdAt int64
	}
)

func NewTestRefreshToken(authId int64, token string, expiresIn, createdAt int64) *TestRefreshToken {
	return &TestRefreshToken{authId, token, expiresIn, createdAt}
}

func (t *TestRefreshToken) AuthId() int64 {
	return t.authId
}

func (t *TestRefreshToken) Token() string {
	return t.token
}

func (t *TestRefreshToken) ExpiresIn() int64 {
	return t.expiresIn
}

func (t *TestRefreshToken) CreatedAt() int64 {
	return t.createdAt
}
