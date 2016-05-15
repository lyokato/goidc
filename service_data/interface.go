package service_data

type (
	ClientInterface interface {
		Id() string
		OwnerUserId() int64
		IdTokenAlg() string
		IdTokenKeyId() string
		IdTokenKey() interface{}
		MatchSecret(secret string) bool
		CanUseGrantType(gt string) bool
		CanUseScope(scope string) bool
		CanUseRedirectURI(uri string) bool
		AssertionKey(alg, kid string) interface{}
	}

	AuthInfoInterface interface {
		Id() int64
		FlowType() string

		ClientId() string
		UserId() int64
		Scope() string
		AuthTime() int64

		// ID Token specific values

		// Subject: If you support PPID, generate unique ID for each client, or not, just return string same as UserId
		Subject() string
		IdTokenExpiresIn() int64

		// Session specific Values
		RedirectURI() string
		Code() string
		CodeExpiresIn() int64
		CodeVerifier() string
		Nonce() string
	}

	OAuthTokenInterface interface {
		AuthId() int64

		AccessToken() string
		AccessTokenExpiresIn() int64
		RefreshedAt() int64

		RefreshToken() string
		RefreshTokenExpiresIn() int64
		CreatedAt() int64
	}

	AuthSession struct {
		RedirectURI   string
		Code          string
		CodeExpiresIn int64
		CodeVerifier  string
		Nonce         string
		AuthTime      int64
	}

	ServiceDataInterface interface {
		Issuer() string
		FindClientById(clientId string) (ClientInterface, *Error)
		FindAuthInfoByCode(code string) (AuthInfoInterface, *Error)
		FindAuthInfoById(id int64) (AuthInfoInterface, *Error)
		FindOAuthTokenByAccessToken(token string) (OAuthTokenInterface, *Error)
		FindOAuthTokenByRefreshToken(token string) (OAuthTokenInterface, *Error)
		CreateOAuthToken(info AuthInfoInterface) (OAuthTokenInterface, *Error)
		RefreshAccessToken(info AuthInfoInterface, token OAuthTokenInterface) (OAuthTokenInterface, *Error)
		FindUserId(username, password string) (int64, *Error)
		CreateOrUpdateAuthInfo(uid int64, clientId, scope string, session *AuthSession) (AuthInfoInterface, *Error)

		FindUserIdBySubject(sub string) (int64, *Error)
		RecordAssertionClaims(clientId, jti string, issuedAt, expiredAt int64) *Error
	}
)
