package test_helper

type (
	TestClient struct {
		id           string
		ownerId      int64
		secret       string
		redirectURI  string
		idTokenAlg   string
		idTokenKeyId string
		idTokenKey   interface{}
		grantTypes   map[string]bool
		Enabled      bool
	}
)

func NewTestClient(ownerId int64, id, secret, redirectURI, alg string, key interface{}, keyId string) *TestClient {
	return &TestClient{
		ownerId:      ownerId,
		id:           id,
		secret:       secret,
		redirectURI:  redirectURI,
		idTokenAlg:   alg,
		idTokenKey:   key,
		idTokenKeyId: keyId,
		grantTypes:   make(map[string]bool, 0),
		Enabled:      true,
	}
}

func (c *TestClient) AllowToUseGrantType(gt string) {
	c.grantTypes[gt] = true
}

func (c *TestClient) CanUseGrantType(gt string) bool {
	allowed, exists := c.grantTypes[gt]
	if exists {
		return allowed
	} else {
		return false
	}
}

func (c *TestClient) CanUseRedirectURI(url string) bool {
	return (c.redirectURI == url)
}

func (c *TestClient) CanUseScope(scope string) bool {
	return true
}

func (c *TestClient) OwnerUserId() int64 {
	return c.ownerId
}

func (c *TestClient) Id() string {
	return c.id
}

func (c *TestClient) MatchSecret(secret string) bool {
	return c.secret == secret
}

func (c *TestClient) IdTokenAlg() string {
	return c.idTokenAlg
}

func (c *TestClient) IdTokenKeyId() string {
	return c.idTokenKeyId
}

func (c *TestClient) IdTokenKey() interface{} {
	return c.idTokenKey
}
