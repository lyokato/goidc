package test_helper

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/lyokato/goidc/authorizer"
	"github.com/lyokato/goidc/crypto"
	"github.com/lyokato/goidc/scope"
	sd "github.com/lyokato/goidc/service_data"
)

type (
	TestUser struct {
		Id       int64
		Username string
		Password string
	}

	TestStore struct {
		privKey       *rsa.PrivateKey
		userIdPod     int64
		infoIdPod     int64
		users         map[int64]*TestUser
		clients       map[string]*TestClient
		infos         map[int64]*TestAuthInfo
		sessions      map[string]*TestAuthSession
		accessTokenes map[string]*TestOAuthToken
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
		privKey:       privKey,
		userIdPod:     0,
		infoIdPod:     0,
		users:         make(map[int64]*TestUser, 0),
		clients:       make(map[string]*TestClient, 0),
		infos:         make(map[int64]*TestAuthInfo, 0),
		sessions:      make(map[string]*TestAuthSession, 0),
		accessTokenes: make(map[string]*TestOAuthToken, 0),
	}
}

func (s *TestStore) CreateNewUser(name, pass string) *TestUser {
	u := &TestUser{s.userIdPod, name, pass}
	s.users[u.Id] = u
	s.userIdPod++
	return u
}

func (s *TestStore) CreateNewClient(ownerId int64, id, secret, redirectURI string) *TestClient {
	c := NewTestClient(ownerId, id, secret, redirectURI, "RS256", s.privKey, "my_service_key_id")
	s.clients[c.GetId()] = c
	return c
}

func (s *TestStore) CreateOrUpdateAuthInfo(uid int64, clientId, scope string,
	session *authorizer.Session) (sd.AuthInfoInterface, *sd.Error) {

	i, exists := s.findAuthInfoByUserAndClient(uid, clientId)
	if !exists {
		infoId := s.infoIdPod
		i = &TestAuthInfo{
			id:       infoId,
			userId:   uid,
			clientId: clientId,
			Enabled:  true,
		}
		s.infos[infoId] = i
		s.infoIdPod++
	}
	i.subject = fmt.Sprintf("%d", uid)
	i.scope = scope

	if session != nil {
		s.sessions[session.Code] = &TestAuthSession{
			authId:       i.id,
			redirectUri:  session.RedirectURI,
			authTime:     session.AuthTime,
			code:         session.Code,
			expiresIn:    session.ExpiresIn,
			codeVerifier: session.CodeVerifier,
			nonce:        session.Nonce,
		}
	}
	return i, nil
}

func (s *TestStore) findAuthInfoByUserAndClient(uid int64, clientId string) (*TestAuthInfo, bool) {
	for _, i := range s.infos {
		if i.GetUserId() == uid && i.GetClientId() == clientId {
			return i, true
		}
	}
	return nil, false
}

func (s *TestStore) ClearAuthData() {
	s.infoIdPod = 0
	s.infos = make(map[int64]*TestAuthInfo, 0)
	s.sessions = make(map[string]*TestAuthSession, 0)
	s.accessTokenes = make(map[string]*TestOAuthToken, 0)
}

func (s *TestStore) ClearAll() {
	s.ClearAuthData()
	s.userIdPod = 0
	s.users = make(map[int64]*TestUser, 0)
	s.clients = make(map[string]*TestClient, 0)
}

// ServiceDataInterface
func (s *TestStore) Issuer() string {
	return "http://example.org/"
}

func (s *TestStore) FindUserId(username, password string) (int64, *sd.Error) {
	for _, u := range s.users {
		if u.Username == username && u.Password == password {
			return u.Id, nil
		}
	}
	return -1, sd.NewError(sd.ErrFailed)
}

func (s *TestStore) FindClientById(cid string) (sd.ClientInterface, *sd.Error) {
	c, exists := s.clients[cid]
	if !exists {
		// not found
		return nil, sd.NewError(sd.ErrFailed)
	}
	return c, nil
}

func (s *TestStore) FindAuthSessionByCode(code string) (sd.AuthSessionInterface, *sd.Error) {
	sess, exists := s.sessions[code]
	if !exists {
		// not found
		return nil, sd.NewError(sd.ErrFailed)
	}
	return sess, nil
}

func (s *TestStore) FindAuthInfoById(id int64) (sd.AuthInfoInterface, *sd.Error) {
	i, exists := s.infos[id]
	if !exists {
		return nil, sd.NewError(sd.ErrFailed)
	}
	return i, nil
}

func (s *TestStore) FindOAuthTokenByAccessToken(token string) (sd.OAuthTokenInterface, *sd.Error) {
	at, exists := s.accessTokenes[token]
	if !exists {
		return nil, sd.NewError(sd.ErrFailed)
	}
	return at, nil
}

func (s *TestStore) FindOAuthTokenByRefreshToken(token string) (sd.OAuthTokenInterface, *sd.Error) {
	for _, at := range s.accessTokenes {
		if at.GetRefreshToken() == token {
			return at, nil
		}
	}
	return nil, sd.NewError(sd.ErrFailed)
}

func (s *TestStore) DisableSession(sess sd.AuthSessionInterface) *sd.Error {
	delete(s.sessions, sess.GetCode())
	return nil
}

func (s *TestStore) CreateOAuthToken(info sd.AuthInfoInterface) (sd.OAuthTokenInterface, *sd.Error) {
	avalue := fmt.Sprintf("ACCESS_TOKEN_%d", info.GetId())
	rvalue := fmt.Sprintf("REFRESH_TOKEN_%d", info.GetId())
	if !scope.IncludeOfflineAccess(info.GetScope()) {
		rvalue = ""
	}
	t := NewTestOAuthToken(info.GetId(), avalue, 60*60*24, time.Now().Unix(),
		rvalue, 60*60*24*30, time.Now().Unix())
	s.accessTokenes[t.GetAccessToken()] = t
	return t, nil
}

func (s *TestStore) RecordAssertionClaims(sub, jti string, iat, exp int64) *sd.Error {
	return nil
}

func (s *TestStore) FindUserIdBySubject(sub string) (int64, *sd.Error) {
	for _, u := range s.users {
		if u.Username == sub {
			return u.Id, nil
		}
	}
	return -1, sd.NewError(sd.ErrFailed)
}

func (s *TestStore) RefreshAccessToken(info sd.AuthInfoInterface, old sd.OAuthTokenInterface) (sd.OAuthTokenInterface, *sd.Error) {
	oldToken := old.GetAccessToken()
	token, _ := s.accessTokenes[oldToken]
	token.accessToken = token.accessToken + ":R"
	token.accessTokenExpiresIn = 60 * 60 * 24
	token.refreshedAt = time.Now().Unix()

	delete(s.accessTokenes, oldToken)
	s.accessTokenes[token.accessToken] = token
	return token, nil
}
