package service_data

type (
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

	AuthInfo struct {
		id          int64
		flowType    string
		clientId    string
		userId      int64
		redirectUri string
		subject     string
		scope       string

		idTokenExpiresIn int64

		authorizedAt int64

		code          string
		codeExpiresIn int64
		codeVerifier  string
		nonce         string
	}
)

func (i *AuthInfo) Id() int64 {
	return i.id
}

func (i *AuthInfo) AuthorizedAt() int64 {
	return i.authorizedAt
}

func (i *AuthInfo) IDTokenExpiresIn() int64 {
	return i.idTokenExpiresIn
}

func (i *AuthInfo) FlowType() string {
	return i.flowType
}

func (i *AuthInfo) ClientId() string {
	return i.clientId
}

func (i *AuthInfo) Code() string {
	return i.code
}

func (i *AuthInfo) Scope() string {
	return i.scope
}

func (i *AuthInfo) CodeExpiresIn() int64 {
	return i.codeExpiresIn
}

func (i *AuthInfo) CodeVerifier() string {
	return i.codeVerifier
}

func (i *AuthInfo) RedirectURI() string {
	return i.redirectUri
}

func (i *AuthInfo) UserId() int64 {
	return i.userId
}

func (i *AuthInfo) Subject() string {
	return i.subject
}

func (i *AuthInfo) Nonce() string {
	return i.nonce
}
