package service_data

import (
	oer "github.com/lyokato/goidc/oauth_error"
)

type (
	ClientInterface interface {
		Id() string
		Secret() string
		RedirectURI() string
		IdTokenAlg() string
		IdTokenKeyId() string
		IdTokenKey() interface{}
	}

	AuthInfoInterface interface {
		Id() int64
		FlowType() string

		ClientId() string
		UserId() int64
		// Subject: If you support PPID, generate unique ID for each client, or not, just return string same as UserId
		Subject() string
		RedirectURI() string
		Scope() string
		AuthorizedAt() int64

		IDTokenExpiresIn() int64

		// Session
		Code() string
		CodeExpiresIn() int64
		CodeVerifier() string

		Nonce() string
	}

	AccessTokenInterface interface {
		AuthId() int64

		AccessToken() string
		AccessTokenExpiresIn() int64
		RefreshedAt() int64

		RefreshToken() string
		RefreshTokenExpiresIn() int64
		CreatedAt() int64
	}

	ServiceDataInterface interface {
		/*
			Issure:
			returns issure name which used in id_token,
			for instance, you may set your service's URL

			Required on AuthroizationCode/Implicit when AuthInfo has openid scope
		*/
		Issure() string
		/*
			FindValidClient
			( Required by All grant handlers )
			search client by given cid(client id), and check if the sec(client secret) is matched for the client's one, and also check if it's allowed to use this grant type. If not, you should return error.
		*/
		FindValidClient(cid, sec, gt string) (ClientInterface, *oer.OAuthError)
		FindAuthInfoByCode(code string) (AuthInfoInterface, *oer.OAuthError)
		FindAuthInfoById(id int64) (AuthInfoInterface, *oer.OAuthError)
		FindAccessTokenByAccessToken(token string) (AccessTokenInterface, *oer.OAuthError)
		FindAccessTokenByRefreshToken(token string) (AccessTokenInterface, *oer.OAuthError)
		CreateAccessToken(info AuthInfoInterface, offlineAccess bool) (AccessTokenInterface, *oer.OAuthError)
		RefreshAccessToken(info AuthInfoInterface, token AccessTokenInterface, offlineAccess bool) (AccessTokenInterface, *oer.OAuthError)

		// for ClientCredential/Password Grant Handler
		FindUserId(username, password string) (int64, *oer.OAuthError)
		FindClientUserId(cid, sec string) (int64, *oer.OAuthError)
		CreateOrUpdateAuthInfo(uid int64, clientId, redirectURI, subject, scope string,
			authroizedAt int64, code string, codeExpiresIn int64, codeVerifier, nonce string) (AuthInfoInterface, *oer.OAuthError)
		CreateOrUpdateAuthInfoDirect(uid int64, clientId, scope string) (AuthInfoInterface, *oer.OAuthError)
	}
)
