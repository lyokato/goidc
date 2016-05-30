package bridge

import (
	"github.com/lyokato/goidc/authorizer"
	"github.com/lyokato/goidc/flow"
	"github.com/lyokato/goidc/prompt"
)

type (
	ClientInterface interface {
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

	AuthInfoInterface interface {
		GetId() int64
		GetClientId() string
		GetUserId() int64
		// Subject: If you support PPID, generate unique ID for each client, or not, just return string same as UserId
		GetSubject() string
		GetScope() string
		GetAuthorizedAt() int64
		IsActive() bool
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
		GetCreatedAt() int64
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

	AuthorizerInterface interface {
		RenderErrorPage(locale string, authErrType int)
		ChooseLocale(locales string) string
		Redirect(url string)
		RedirectToLogin(req *authorizer.Request)
		ConfirmLoginSession(locale string) bool
		RequestIsFromLogin() bool
		GetAuthTime() (int64, *Error)
		GetLoginUserId() int64
		ShowConsentScreen(locale, display string, req *authorizer.Request)
		CreateUniqueCode() (string, *Error)
	}

	ServiceDataInterface interface {
		Issuer() string
		FindClientById(clientId string) (ClientInterface, *Error)
		FindAuthSessionByCode(code string) (AuthSessionInterface, *Error)
		FindActiveAuthInfoById(id int64) (AuthInfoInterface, *Error)
		FindAuthInfoByUserIdAndClientId(uid int64, clientId string) (AuthInfoInterface, *Error)
		FindOAuthTokenByAccessToken(token string) (OAuthTokenInterface, *Error)
		FindOAuthTokenByRefreshToken(token string) (OAuthTokenInterface, *Error)
		CreateOAuthToken(info AuthInfoInterface, onTokenEndpoint bool) (OAuthTokenInterface, *Error)
		RefreshAccessToken(info AuthInfoInterface, token OAuthTokenInterface) (OAuthTokenInterface, *Error)
		FindUserId(username, password string) (int64, *Error)
		CreateOrUpdateAuthInfo(uid int64, clientId, scope string) (AuthInfoInterface, *Error)
		CreateAuthSession(info AuthInfoInterface, session *authorizer.Session) *Error
		DisableSession(sess AuthSessionInterface) *Error
		FindUserIdBySubject(sub string) (int64, *Error)
		RecordAssertionClaims(clientId, jti string, issuedAt, expiredAt int64) *Error
	}
)
