package oauth2

import (
	"net/url"
	"strings"
	"time"

	"github.com/satori/go.uuid"
)

type TestProvider struct {
	client              Client
	authzCodes          map[string]AuthzCode
	accessTokens        map[string]Token
	refreshTokens       map[string]Token
	isUserAuthenticated bool
}

func NewTestProvider(isUserAuthenticated bool) *TestProvider {
	p := &TestProvider{
		authzCodes:    make(map[string]AuthzCode),
		accessTokens:  make(map[string]Token),
		refreshTokens: make(map[string]Token),
	}

	p.isUserAuthenticated = isUserAuthenticated

	c := Client{
		ID:   uuid.NewV4().String(),
		Name: "Test Client",
	}
	c.RedirectURL, _ = url.Parse("https://example.com/oauth2/callback")

	p.client = c
	return p
}

func (p *TestProvider) ClientInfo(clientID string) (Client, error) {
	return p.client, nil
}

func (p *TestProvider) GenAuthzCode(client Client, scopes []Scope) (AuthzCode, error) {
	a := AuthzCode{
		Code:        uuid.NewV4().String(),
		ClientID:    client.ID,
		RedirectURL: client.RedirectURL,
		Scope:       scopes,
	}
	a.ExpiresIn, _ = time.ParseDuration("1m")

	p.authzCodes[a.Code] = a
	return a, nil
}

func (p *TestProvider) RevokeAuthzCode(code string) error {
	delete(p.authzCodes, code)
	return nil
}

func (p *TestProvider) ScopesInfo(scopes string) ([]Scope, error) {
	s := strings.Split(scopes, " ")
	scope := make([]Scope, 0)
	for _, v := range s {
		scope = append(scope, Scope{
			ID:   v,
			Desc: "test scope",
		})
	}
	return scope, nil
}

func (p *TestProvider) GenToken(tokenType TokenType, scopes []Scope, client Client) (Token, error) {
	t := Token{
		Value:    uuid.NewV4().String(),
		Type:     string(tokenType),
		Scope:    scopes,
		ClientID: client.ID,
	}

	t.ExpiresIn, _ = time.ParseDuration("10m")
	p.accessTokens[t.Value] = t
	return t, nil
}

func (p *TestProvider) RevokeToken(token string) error {
	delete(p.accessTokens, token)
	return nil
}

func (p *TestProvider) RefreshToken(refreshToken, scopes []Scope) (Token, error) {
	return Token{}, nil
}

func (p *TestProvider) AuthzForm() string {
	return "test"
}

func (p *TestProvider) LoginURL(refererURL string) string {
	return "https://www.example.com/accounts/login?redirect_to=" + refererURL
}

func (p *TestProvider) IsUserAuthenticated() bool {
	return p.isUserAuthenticated
}
