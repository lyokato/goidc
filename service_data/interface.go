package service_data

type (
	ClientInterface interface {
		GetId() string
		GetOwnerUserId() int64
		GetIdTokenAlg() string
		GetIdTokenKeyId() string
		GetIdTokenKey() interface{}
		MatchSecret(secret string) bool
		CanUseGrantType(gt string) bool
		CanUseScope(scope string) bool
		CanUseRedirectURI(uri string) bool
		GetAssertionKey(alg, kid string) interface{}
	}

	AuthInfoInterface interface {
		GetId() int64
		GetFlowType() string

		GetClientId() string
		GetUserId() int64
		GetScope() string
		GetAuthTime() int64

		// ID Token specific values

		// Subject: If you support PPID, generate unique ID for each client, or not, just return string same as UserId
		GetSubject() string
		GetIdTokenExpiresIn() int64

		// Session specific Values
		GetRedirectURI() string
		GetCode() string
		GetCodeExpiresIn() int64
		GetCodeVerifier() string
		GetNonce() string
	}

	OAuthTokenInterface interface {
		GetAuthId() int64

		GetAccessToken() string
		GetAccessTokenExpiresIn() int64
		GetRefreshedAt() int64

		GetRefreshToken() string
		GetRefreshTokenExpiresIn() int64
		GetCreatedAt() int64
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
