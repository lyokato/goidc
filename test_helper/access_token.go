package test_helper

type (
	TestAccessToken struct {
		authId int64

		accessToken          string
		accessTokenExpiresIn int64
		refreshedAt          int64

		refreshToken          string
		refreshTokenExpiresIn int64
		createdAt             int64
	}
)

func NewTestAccessToken(authId int64, accessToken string, accessTokenExpiresIn, refreshedAt int64,
	refreshToken string, refreshTokenExpiresIn, createdAt int64) *TestAccessToken {
	return &TestAccessToken{authId, accessToken, accessTokenExpiresIn, refreshedAt, refreshToken, refreshTokenExpiresIn, createdAt}
}

func (t *TestAccessToken) AuthId() int64 {
	return t.authId
}

func (t *TestAccessToken) AccessToken() string {
	return t.accessToken
}

func (t *TestAccessToken) AccessTokenExpiresIn() int64 {
	return t.accessTokenExpiresIn
}

func (t *TestAccessToken) RefreshToken() string {
	return t.refreshToken
}

func (t *TestAccessToken) RefreshTokenExpiresIn() int64 {
	return t.refreshTokenExpiresIn
}

func (t *TestAccessToken) RefreshedAt() int64 {
	return t.refreshedAt
}

func (t *TestAccessToken) CreatedAt() int64 {
	return t.createdAt
}
