package service_data

type (
	AccessTokenInterface interface {
		AuthId() int64
		Token() string
		ExpiresIn() int64
		CreatedAt() int64 // epoch
	}

	AccessToken struct {
		authId    int64
		token     string
		expiresIn int64
		createdAt int64
	}
)

func NewAccessToken(authId int64, token string, expiresIn, createdAt int64) *AccessToken {
	return &AccessToken{authId, token, expiresIn, createdAt}
}

func (t *AccessToken) AuthId() int64 {
	return t.authId
}

func (t *AccessToken) Token() string {
	return t.token
}

func (t *AccessToken) ExpiresIn() int64 {
	return t.expiresIn
}

func (t *AccessToken) CreatedAt() int64 {
	return t.createdAt
}
