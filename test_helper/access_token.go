package test_helper

type (
	TestAccessToken struct {
		authId    int64
		token     string
		expiresIn int64
		createdAt int64
	}
)

func NewTestAccessToken(authId int64, token string, expiresIn, createdAt int64) *TestAccessToken {
	return &TestAccessToken{authId, token, expiresIn, createdAt}
}

func (t *TestAccessToken) AuthId() int64 {
	return t.authId
}

func (t *TestAccessToken) Token() string {
	return t.token
}

func (t *TestAccessToken) ExpiresIn() int64 {
	return t.expiresIn
}

func (t *TestAccessToken) CreatedAt() int64 {
	return t.createdAt
}
