package service_data

type (
	ClientInterface interface {
		Id() string
		Secret() string
		RedirectURI() string
		OwnerUserId() int64
		IdTokenAlg() string
		IdTokenKeyId() string
		IdTokenKey() interface{}
		CanUseGrantType(gt string) bool
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

	AuthSession struct {
		RedirectURI   string
		Code          string
		CodeExpiresIn int64
		CodeVerifier  string
		Nonce         string
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
		FindClientById(clientId string) (ClientInterface, *Error)
		FindAuthInfoByCode(code string) (AuthInfoInterface, *Error)
		FindAuthInfoById(id int64) (AuthInfoInterface, *Error)
		FindAccessTokenByAccessToken(token string) (AccessTokenInterface, *Error)
		FindAccessTokenByRefreshToken(token string) (AccessTokenInterface, *Error)
		CreateAccessToken(info AuthInfoInterface, offlineAccess bool) (AccessTokenInterface, *Error)
		RefreshAccessToken(info AuthInfoInterface, token AccessTokenInterface, offlineAccess bool) (AccessTokenInterface, *Error)

		// for ClientCredential/Password Grant Handler
		FindUserId(username, password string) (int64, *Error)
		CreateOrUpdateAuthInfo(uid int64, clientId, scope string, session *AuthSession) (AuthInfoInterface, *Error)
	}
)
