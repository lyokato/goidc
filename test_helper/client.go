package test_helper

type (
	TestClient struct {
		id          string
		secret      string
		redirectURI string
		idTokenAlg  string
		idTokenKey  interface{}
		Enabled     bool
	}
)

func NewTestClient(id, secret, redirectURI, alg string, key interface{}) *TestClient {
	return &TestClient{
		id:          id,
		secret:      secret,
		redirectURI: redirectURI,
		idTokenAlg:  alg,
		idTokenKey:  key,
		Enabled:     true,
	}
}

func (c *TestClient) Id() string {
	return c.id
}

func (c *TestClient) Secret() string {
	return c.secret
}

func (c *TestClient) RedirectURI() string {
	return c.redirectURI
}

func (c *TestClient) IdTokenAlg() string {
	return c.idTokenAlg
}

func (c *TestClient) IdTokenKey() interface{} {
	return c.idTokenKey
}
