package test_helper

type (
	TestOAuthToken struct {
		authId int64

		accessToken          string
		accessTokenExpiresIn int64
		refreshedAt          int64

		refreshToken          string
		refreshTokenExpiresIn int64
		createdAt             int64
	}
)

func NewTestOAuthToken(authId int64, accessToken string, accessTokenExpiresIn, refreshedAt int64,
	refreshToken string, refreshTokenExpiresIn, createdAt int64) *TestOAuthToken {
	return &TestOAuthToken{authId, accessToken, accessTokenExpiresIn, refreshedAt, refreshToken, refreshTokenExpiresIn, createdAt}
}

func (t *TestOAuthToken) AuthId() int64 {
	return t.authId
}

func (t *TestOAuthToken) AccessToken() string {
	return t.accessToken
}

func (t *TestOAuthToken) AccessTokenExpiresIn() int64 {
	return t.accessTokenExpiresIn
}

func (t *TestOAuthToken) RefreshToken() string {
	return t.refreshToken
}

func (t *TestOAuthToken) RefreshTokenExpiresIn() int64 {
	return t.refreshTokenExpiresIn
}

func (t *TestOAuthToken) RefreshedAt() int64 {
	return t.refreshedAt
}

func (t *TestOAuthToken) CreatedAt() int64 {
	return t.createdAt
}
