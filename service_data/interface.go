package service_data

import (
	"github.com/lyokato/goidc/authorizer"
)

type (
	ClientInterface interface {
		GetId() string
		GetOwnerUserId() int64
		GetIdTokenAlg() string
		GetIdTokenKeyId() string
		GetIdTokenKey() interface{}
		MatchSecret(secret string) bool
		CanUseFlow(flow *authorizer.Flow) bool
		CanUseGrantType(gt string) bool
		CanUseScope(flowType authorizer.FlowType, scope string) bool
		CanUseRedirectURI(uri string) bool
		GetAssertionKey(alg, kid string) interface{}
	}

	AuthInfoInterface interface {
		GetId() int64

		GetClientId() string
		GetUserId() int64
		// Subject: If you support PPID, generate unique ID for each client, or not, just return string same as UserId
		GetSubject() string
		GetScope() string
	}

	AuthSessionInterface interface {
		GetCode() string
		GetAuthId() int64
		GetAuthTime() int64
		GetIdTokenExpiresIn() int64
		GetRedirectURI() string
		GetCodeVerifier() string
		GetExpiresIn() int64
		GetNonce() string
		GetAuthorizedAt() int64
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

	ServiceDataInterface interface {
		Issuer() string
		FindClientById(clientId string) (ClientInterface, *Error)
		FindAuthSessionByCode(code string) (AuthSessionInterface, *Error)
		FindAuthInfoById(id int64) (AuthInfoInterface, *Error)
		FindOAuthTokenByAccessToken(token string) (OAuthTokenInterface, *Error)
		FindOAuthTokenByRefreshToken(token string) (OAuthTokenInterface, *Error)
		CreateOAuthToken(info AuthInfoInterface) (OAuthTokenInterface, *Error)
		RefreshAccessToken(info AuthInfoInterface, token OAuthTokenInterface) (OAuthTokenInterface, *Error)
		FindUserId(username, password string) (int64, *Error)
		CreateOrUpdateAuthInfo(uid int64, clientId, scope string, session *authorizer.Session) (AuthInfoInterface, *Error)
		DisableSession(sess AuthSessionInterface) *Error
		FindUserIdBySubject(sub string) (int64, *Error)
		RecordAssertionClaims(clientId, jti string, issuedAt, expiredAt int64) *Error
	}
)
