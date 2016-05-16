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
		authTime      int64
		code          string
		codeExpiresIn int64
		codeVerifier  string
		nonce         string
		Enabled       bool
	}
)

func (i *TestAuthInfo) GetId() int64 {
	return i.id
}

func (i *TestAuthInfo) GetAuthTime() int64 {
	return i.authTime
}

func (i *TestAuthInfo) GetIdTokenExpiresIn() int64 {
	return int64(60 * 60 * 24 * 7)
}

func (i *TestAuthInfo) GetFlowType() string {
	return i.flowType
}

func (i *TestAuthInfo) GetClientId() string {
	return i.clientId
}

func (i *TestAuthInfo) GetCode() string {
	return i.code
}

func (i *TestAuthInfo) GetScope() string {
	return i.scope
}

func (i *TestAuthInfo) GetCodeExpiresIn() int64 {
	return i.codeExpiresIn
}

func (i *TestAuthInfo) GetCodeVerifier() string {
	return i.codeVerifier
}

func (i *TestAuthInfo) GetRedirectURI() string {
	return i.redirectUri
}

func (i *TestAuthInfo) GetUserId() int64 {
	return i.userId
}

func (i *TestAuthInfo) GetSubject() string {
	return i.subject
}

func (i *TestAuthInfo) GetNonce() string {
	return i.nonce
}
