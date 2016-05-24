package test_helper

type (
	TestAuthInfo struct {
		id       int64
		clientId string
		userId   int64
		scope    string
		subject  string

		Enabled bool
	}
)

func (i *TestAuthInfo) GetId() int64 {
	return i.id
}

func (i *TestAuthInfo) GetClientId() string {
	return i.clientId
}

func (i *TestAuthInfo) GetScope() string {
	return i.scope
}

func (i *TestAuthInfo) GetUserId() int64 {
	return i.userId
}

func (i *TestAuthInfo) GetSubject() string {
	return i.subject
}
