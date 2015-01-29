package test

import (
	"html/template"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/hooklift/oauth2/pkg"
	"github.com/hooklift/oauth2/types"
	"github.com/satori/go.uuid"
)

type Provider struct {
	Client              types.Client
	AuthzCodes          map[string]types.AuthzCode
	AccessTokens        map[string]types.Token
	RefreshTokens       map[string]types.Token
	isUserAuthenticated bool
}

func NewProvider(isUserAuthenticated bool) *Provider {
	p := &Provider{
		AuthzCodes:    make(map[string]types.AuthzCode),
		AccessTokens:  make(map[string]types.Token),
		RefreshTokens: make(map[string]types.Token),
	}

	p.isUserAuthenticated = isUserAuthenticated

	c := types.Client{
		ID:   uuid.NewV4().String(),
		Name: "Test Client",
	}
	c.RedirectURL, _ = url.Parse("https://example.com/oauth2/callback")

	p.Client = c
	return p
}

func (p *Provider) ClientInfo(clientID string) (types.Client, error) {
	return p.Client, nil
}

func (p *Provider) GenAuthzCode(client types.Client, scopes []types.Scope) (types.AuthzCode, error) {
	a := types.AuthzCode{
		Code:        uuid.NewV4().String(),
		ClientID:    client.ID,
		RedirectURL: client.RedirectURL,
		Scope:       scopes,
	}
	a.ExpiresIn = p.AuthzExpiration()

	p.AuthzCodes[a.Code] = a
	return a, nil
}

func (p *Provider) RevokeAuthzCode(code string) error {
	delete(p.AuthzCodes, code)
	return nil
}

func (p *Provider) ScopesInfo(scopes string) ([]types.Scope, error) {
	s := strings.Split(scopes, " ")
	scope := make([]types.Scope, 0)
	for _, v := range s {
		scope = append(scope, types.Scope{
			ID:   v,
			Desc: "test scope",
		})
	}
	return scope, nil
}

func (p *Provider) GenToken(tokenType types.TokenType, scopes []types.Scope, client types.Client) (types.Token, error) {
	t := types.Token{
		Value:    uuid.NewV4().String(),
		Type:     "bearer",
		Scope:    scopes,
		ClientID: client.ID,
	}

	t.ExpiresIn = p.TokenExpiration()
	p.AccessTokens[t.Value] = t
	return t, nil
}

func (p *Provider) RevokeToken(token string) error {
	delete(p.AccessTokens, token)
	return nil
}

func (p *Provider) RefreshToken(refreshToken, scopes []types.Scope) (types.Token, error) {
	return types.Token{}, nil
}

func (p *Provider) AuthzForm() *template.Template {
	t := template.New("authzform")
	t.Funcs(template.FuncMap{
		"StringifyScopes": pkg.StringifyScopes,
	})

	form := `
		<html>
		<body>
		{{if .Errors}}
			<div id="errors">
				<ul>
				{{range .Errors}}
					<li>{{.Code}}: {{.Desc}}</li>
				{{end}}
				</ul>
			</div>
		{{else}}
			<div id="client">
				<h2>{{.Client.Name}}</h2>
				<h3>{{.Client.Desc}}</h3>
				<a href="{{.Client.HomepageURL}}">
					<figure><img src="{{.Client.ProfileImgURL}}"/></figure>
				</a>
			</div>
			<div id="scopes">
				<ul>
					{{range .Scopes}}
						<li>{{.ID}}: {{.Desc}}</li>
					{{end}}
				</ul>
			</div>
			<form>
			 <input type="hidden" name="client_id" value="{{.Client.ID}}"/>
			 <input type="hidden" name="response_type" value="{{.GrantType}}"/>
			 <input type="hidden" name="redirect_uri" value="{{.Client.RedirectURL}}"/>
			 <input type="hidden" name="scope" value="{{StringifyScopes .Scopes}}"/>
			 <input type="hidden" name="state" value="{{.State}}"/>
			</form>
		{{end}}
		</body>
		</html>
	`

	tpl, err := t.Parse(form)
	if err != nil {
		log.Fatalf("Error parsing authorization form: %v", err)
	}

	return tpl

}

func (p *Provider) TokenEndpoint() string {
	return "/oauth2/tokens"
}

func (p *Provider) AuthzEndpoint() string {
	return "/oauth2/authzs"
}

func (p *Provider) RevokeEndpoint() string {
	return "/oauth2/revoke"
}

func (p *Provider) TokenExpiration() time.Duration {
	t, err := time.ParseDuration("10m")
	if err != nil {
		log.Fatalln(err)
	}
	return t
}

func (p *Provider) AuthzExpiration() time.Duration {
	t, err := time.ParseDuration("1m")
	if err != nil {
		log.Fatalln(err)
	}

	return t
}

func (p *Provider) STSMaxAge() time.Duration {
	t, err := time.ParseDuration("0s")
	if err != nil {
		log.Fatalln(err)
	}

	return t
}

func (p *Provider) LoginURL(refererURL string) string {
	return "https://www.example.com/accounts/login?redirect_to=" + refererURL
}

func (p *Provider) IsUserAuthenticated() bool {
	return p.isUserAuthenticated
}
