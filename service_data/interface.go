package service_data

import (
	oer "github.com/lyokato/goidc/oauth_error"
)

type ServiceDataInterface interface {
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
	FindAccessToken(token string) (AccessTokenInterface, *oer.OAuthError)
	FindRefreshToken(token string) (RefreshTokenInterface, *oer.OAuthError)
	CreateAccessToken(info AuthInfoInterface) (AccessTokenInterface, *oer.OAuthError)
	CreateRefreshToken(info AuthInfoInterface) (RefreshTokenInterface, *oer.OAuthError)

	// for ClientCredential/Password Grant Handler
	//FindUserId(username, password string) (string, *oer.OAuthError)
	//CreateOrUpdateAuthInfo(userId, clientId, scope string) (AuthInfoInterface, *oer.OAuthError)
}
