package grant

import (
	"fmt"
	"net/http"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lyokato/goidc/id_token"

	"github.com/lyokato/goidc/scope"

	oer "github.com/lyokato/goidc/oauth_error"
	"github.com/lyokato/goidc/pkce"
	sd "github.com/lyokato/goidc/service_data"
)

func AuthorizationCode() *GrantHandler {
	return &GrantHandler{
		"authorization_code",
		func(r *http.Request, c sd.ClientInterface,
			sdi sd.ServiceDataInterface) (*Response, *oer.OAuthError) {

			uri := r.FormValue("redirect_uri")
			if uri == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			code := r.FormValue("code")
			if code == "" || uri == "" {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			info, err := sdi.FindAuthInfoByCode(code)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			if info.ClientId() != c.Id() {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			if info.RedirectURI() != uri {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			// RFC7636: OAuth PKCE Extension
			cv := info.CodeVerifier()
			if cv != "" {
				cm := r.FormValue("code_challenge_method")
				if cm == "" {
					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						"missing 'code_challenge_method'")
				}
				cc := r.FormValue("code_challenge")
				if cc == "" {
					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						"missing 'code_challenge'")
				}
				verifier, err := pkce.FindVerifierByMethod(cm)
				if err != nil {
					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						fmt.Sprintf("unsupported code_challenge_method: %s", cm))
				}
				if !verifier.Verify(cc, cv) {
					return nil, oer.NewOAuthError(oer.ErrInvalidRequest,
						fmt.Sprintf("invalid code_challenge: %s", cc))
				}
			}

			token, err := sdi.CreateAccessToken(info)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}

			res := NewResponse(token.Token(), token.ExpiresIn())
			scp := info.Scope()
			if scp != "" {
				res.Scope = scp
			}

			rt, err := sdi.CreateRefreshToken(info)
			if err != nil {
				return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
			}
			if rt != nil {
				res.RefreshToken = rt.Token()
			}

			if scope.IncludeOpenID(scp) {
				idt, err := id_token.Gen(jwa.SignatureAlgorithm(c.IdTokenAlg()), c.IdTokenKey(), sdi.Issure(),
					info.ClientId(), info.Subject(), info.Nonce(), info.IDTokenExpiresIn(), info.AuthorizedAt())
				if err != nil {
					// TODO fix error type
					return nil, oer.NewOAuthError(oer.ErrInvalidRequest, "")
				} else {
					res.IdToken = idt
				}
			}
			return res, nil
		},
	}
}
