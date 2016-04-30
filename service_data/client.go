package service_data

type (
	ClientInterface interface {
		Id() string
		Secret() string
		RedirectURI() string
		IdTokenAlg() string
		IdTokenKeyId() string
		IdTokenKey() interface{}
	}

	Client struct {
		id           string
		secret       string
		redirectURI  string
		idTokenAlg   string
		idTokenKey   interface{}
		idTokenKeyId string
	}
)

func NewClient(id, secret, redirectURI, alg string, key interface{}, keyId string) *Client {
	return &Client{
		id:           id,
		secret:       secret,
		redirectURI:  redirectURI,
		idTokenAlg:   alg,
		idTokenKey:   key,
		idTokenKeyId: keyId,
	}
}

func (c *Client) Id() string {
	return c.id
}

func (c *Client) Secret() string {
	return c.secret
}

func (c *Client) RedirectURI() string {
	return c.redirectURI
}

func (c *Client) IdTokenAlg() string {
	return c.idTokenAlg
}

func (c *Client) IdTokenKeyId() string {
	return c.idTokenKeyId
}

func (c *Client) IdTokenKey() interface{} {
	return c.idTokenKey
}
