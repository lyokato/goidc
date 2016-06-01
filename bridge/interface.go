package bridge

import (
	"github.com/lyokato/goidc/authorization"
	"github.com/lyokato/goidc/flow"
	"github.com/lyokato/goidc/prompt"
)

type (
	Client interface {
		GetId() string
		GetOwnerUserId() int64
		GetIdTokenAlg() string
		GetIdTokenKeyId() string
		GetIdTokenKey() interface{}
		MatchSecret(secret string) bool
		CanUseFlow(flowType flow.FlowType) bool
		CanUseGrantType(gt string) bool
		CanUseScope(flowType flow.FlowType, scope string) bool
		CanUseRedirectURI(uri string) bool
		GetAssertionKey(alg, kid string) interface{}
		GetNoConsentPromptPolicy() prompt.NoConsentPromptPolicy
	}

	AuthInfo interface {
		GetId() int64
		GetClientId() string
		GetUserId() int64
		// Subject: If you support PPID, generate unique ID for each client, or not, just return string same as UserId
		GetSubject() string
		GetScope() string
		GetAuthorizedAt() int64
		IsActive() bool
	}

	AuthSession interface {
		GetCode() string
		GetAuthId() int64
		GetAuthTime() int64
		GetIdTokenExpiresIn() int64
		GetRedirectURI() string
		GetCodeVerifier() string
		GetExpiresIn() int64
		GetNonce() string
		GetCreatedAt() int64
	}

	OAuthToken interface {
		GetAuthId() int64

		GetAccessToken() string
		GetAccessTokenExpiresIn() int64
		GetRefreshedAt() int64

		GetRefreshToken() string
		GetRefreshTokenExpiresIn() int64
		GetCreatedAt() int64
	}

	AuthorizationCallbacks interface {
		ShowErrorScreen(authErrType int)
		ShowLoginScreen(req *authorization.Request) error
		ShowConsentScreen(client Client, req *authorization.Request) error
		ChooseLocale(locales string) (string, error)
		ConfirmLoginSession() (bool, error)
		RequestIsFromLogin() (bool, error)
		GetAuthTime() (int64, error)
		GetLoginUserId() (int64, error)
		CreateAuthorizationCode() (string, error)
		Continue() (*authorization.Request, error)
	}

	DataInterface interface {
		Issuer() string
		FindClientById(clientId string) (Client, *Error)
		FindAuthSessionByCode(code string) (AuthSession, *Error)
		FindActiveAuthInfoById(id int64) (AuthInfo, *Error)
		FindAuthInfoByUserIdAndClientId(uid int64, clientId string) (AuthInfo, *Error)
		FindOAuthTokenByAccessToken(token string) (OAuthToken, *Error)
		FindOAuthTokenByRefreshToken(token string) (OAuthToken, *Error)
		CreateOAuthToken(info AuthInfo, onTokenEndpoint bool) (OAuthToken, *Error)
		RefreshAccessToken(info AuthInfo, token OAuthToken) (OAuthToken, *Error)
		FindUserId(username, password string) (int64, *Error)
		CreateOrUpdateAuthInfo(uid int64, clientId, scope string) (AuthInfo, *Error)
		CreateAuthSession(info AuthInfo, session *authorization.Session) *Error
		DisableSession(sess AuthSession) *Error
		FindUserIdBySubject(sub string) (int64, *Error)
		RecordAssertionClaims(clientId, jti string, issuedAt, expiredAt int64) *Error
	}
)
