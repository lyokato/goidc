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

func (c *TestClient) OwnerId() int64 {
	return c.ownerId
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

func (c *TestClient) IdTokenKeyId() string {
	return c.idTokenKeyId
}

func (c *TestClient) IdTokenKey() interface{} {
	return c.idTokenKey
}
