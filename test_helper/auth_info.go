package test_helper

type (
	TestAuthInfo struct {
		id            int64
		flowType      string
		clientId      string
		userId        int64
		redirectUri   string
		subject       string
		scope         string
		authorizedAt  int64
		code          string
		codeExpiresIn int64
		codeVerifier  string
		nonce         string
		Enabled       bool
	}
)

func (i *TestAuthInfo) Id() int64 {
	return i.id
}

func (i *TestAuthInfo) AuthorizedAt() int64 {
	return i.authorizedAt
}

func (i *TestAuthInfo) IDTokenExpiresIn() int64 {
	return int64(60 * 60 * 24 * 7)
}

func (i *TestAuthInfo) FlowType() string {
	return i.flowType
}

func (i *TestAuthInfo) ClientId() string {
	return i.clientId
}

func (i *TestAuthInfo) Code() string {
	return i.code
}

func (i *TestAuthInfo) Scope() string {
	return i.scope
}

func (i *TestAuthInfo) CodeExpiresIn() int64 {
	return i.codeExpiresIn
}

func (i *TestAuthInfo) CodeVerifier() string {
	return i.codeVerifier
}

func (i *TestAuthInfo) RedirectURI() string {
	return i.redirectUri
}

func (i *TestAuthInfo) UserId() int64 {
	return i.userId
}

func (i *TestAuthInfo) Subject() string {
	return i.subject
}

func (i *TestAuthInfo) Nonce() string {
	return i.nonce
}
