package test_helper

import (
	"crypto/rsa"

	"github.com/lyokato/goidc/crypto"
	oer "github.com/lyokato/goidc/oauth_error"
	sd "github.com/lyokato/goidc/service_data"
)

type (
	TestUser struct {
		Id       int64
		Username string
		Password string
	}

	TestStore struct {
		privKey        *rsa.PrivateKey
		userIdPod      int64
		users          map[int64]*TestUser
		clients        map[string]*TestClient
		infos          map[int64]*TestAuthInfo
		accessTokenes  map[string]*sd.AccessToken
		refreshTokenes map[string]*sd.RefreshToken
	}
)

func NewTestStore() *TestStore {

	privKey, _ := crypto.LoadPrivateKeyFromText(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCzFyUUfVGyMCbG7YIwgo4XdqEjhhgIZJ4Kr7VKwIc7F+x0DoBn
iO6uhU6HVxMPibxSDIGQIHoxP9HJPGF1XlEt7EMwewb5Rcku33r+2QCETRmQMw68
eZUZqdtgy1JFCFsFUcMwcVcfTqXU00UEevH9RFBHoqxJsRC0l1ybcs6o0QIDAQAB
AoGBAIICU1DEiQIqInxW/yPoIu61l9UKC3hMUs6/L4TMr18exvCZdm2y4lKfQ5rM
g3HMM4H8wjG24f3OrqS/yKBDj/nnNAWqbhCRF49wn3gp1s/zLSxnHkR1nGmGlr3O
0jb22hR4aw9TFr7uJIe5YuWKWBG47p/cns9iVGV8sXVtrdABAkEA4ZfSD5I3F+rw
BFdB4WwRx7/hgb4kwq3E5GX44AYBvlymPcbDwiXXfC+zhhaZQ+VqZiGH8ecNIB4F
S/IvgkuJMQJBAMs6u13KRs+uSdT9YQ4OTbSAjldgHQKIScc427p7ik+Kg6eNqo1/
RUyRIclFf2s8HmCn6+zfAAk+Z76ocNn7MaECQQCGfp0d624tNEQkUmFUo7l1/U/U
qigAaNkZ0jGuXeZsN5BlBDtxZF40C7xcFN0LPZtRiGwkLDwHCd7eiGUKqT4BAkBJ
2zFGd4Febj+EuQRxgD87DtEr7dD9H5x4WzB3R/hOyc7osHI/8/WySrgVlj0lMnbz
t3Lk5XH06gn33u0MOt6hAkB1Jf6crfjGnoVE2aGt9SApdZIClFjjzcmhTjtHJVTo
tpgdYZY2kFpD7Nv0TxlmCsXf4JL/+Vd7pFtUuZVdNpfy
-----END RSA PRIVATE KEY-----`)
	privKey.Precompute()

	return &TestStore{
		privKey:        privKey,
		userIdPod:      0,
		users:          make(map[int64]*TestUser, 0),
		clients:        make(map[string]*TestClient, 0),
		infos:          make(map[int64]*TestAuthInfo, 0),
		accessTokenes:  make(map[string]*sd.AccessToken, 0),
		refreshTokenes: make(map[string]*sd.RefreshToken, 0),
	}
}

func (s *TestStore) CreateNewUser(name, pass string) *TestUser {
	u := &TestUser{s.userIdPod, name, pass}
	s.users[u.Id] = u
	s.userIdPod++
	return u
}

func (s *TestStore) CreateNewClient(id, secret, redirectURI string) *TestClient {
	c := NewTestClient(id, secret, redirectURI, "RS256", s.privKey)
	s.clients[c.Id()] = c
	return c
}

func (s *TestStore) ClearAuthData() {
	s.infos = make(map[int64]*TestAuthInfo, 0)
	s.accessTokenes = make(map[string]*sd.AccessToken, 0)
	s.refreshTokenes = make(map[string]*sd.RefreshToken, 0)
}

func (s *TestStore) ClearAll() {
	s.ClearAuthData()
	s.userIdPod = 0
	s.users = make(map[int64]*TestUser, 0)
	s.clients = make(map[string]*TestClient, 0)
}

// ServiceDataInterface
func (s *TestStore) Issure() string {
	return "example.org"
}

func (s *TestStore) FindValidClient(cid, sec, gt string) (sd.ClientInterface, *oer.OAuthError) {
	c, exists := s.clients[cid]
	if !exists {
		// not found
		return nil, oer.NewOAuthError(oer.ErrInvalidClient, "", "")
	}
	if c.Secret() == sec {
		// secret mismatch
		return nil, oer.NewOAuthError(oer.ErrInvalidClient, "", "")
	}
	// TODO check if this client is allowed to use this grantType
	return c, nil
}

func (s *TestStore) FindAuthInfoByCode(code string) (sd.AuthInfoInterface, *oer.OAuthError) {
	for _, i := range s.infos {
		if i.Code() == code {
			return i, nil
		}
	}
	// TODO check error type
	return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
}

func (s *TestStore) FindAuthInfoById(id int64) (sd.AuthInfoInterface, *oer.OAuthError) {
	i, exists := s.infos[id]
	if !exists {
		return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
	}
	return i, nil
}

func (s *TestStore) FindAccessToken(token string) (sd.AccessTokenInterface, *oer.OAuthError) {
	at, exists := s.accessTokenes[token]
	if !exists {
		return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
	}
	return at, nil
}

func (s *TestStore) FindRefreshToken(token string) (sd.RefreshTokenInterface, *oer.OAuthError) {
	rt, exists := s.refreshTokenes[token]
	if !exists {
		return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "", "")
	}
	return rt, nil
}

func (s *TestStore) CreateAccessToken(info sd.AuthInfoInterface) (sd.AccessTokenInterface, *oer.OAuthError) {
	info.Id()
	return nil, nil
}

func (s *TestStore) CreateRefreshToken(info sd.AuthInfoInterface) (sd.RefreshTokenInterface, *oer.OAuthError) {
	info.Id()
	return nil, nil
}
