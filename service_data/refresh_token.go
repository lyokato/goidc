package service_data

type (
	RefreshTokenInterface interface {
		AuthId() int64
		Token() string
		ExpiresIn() int64
		CreatedAt() int64 // epoch
	}

	RefreshToken struct {
		authId    int64
		token     string
		expiresIn int64
		createdAt int64
	}
)

func NewRefreshToken(authId int64, token string, expiresIn, createdAt int64) *RefreshToken {
	return &RefreshToken{authId, token, expiresIn, createdAt}
}

func (t *RefreshToken) AuthId() int64 {
	return t.authId
}

func (t *RefreshToken) Token() string {
	return t.token
}

func (t *RefreshToken) ExpiresIn() int64 {
	return t.expiresIn
}

func (t *RefreshToken) CreatedAt() int64 {
	return t.createdAt
}
