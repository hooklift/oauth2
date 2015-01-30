package test

import (
	"html/template"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hooklift/oauth2/pkg"
	"github.com/hooklift/oauth2/types"
	"github.com/satori/go.uuid"
)

type Provider struct {
	Client              types.Client
	GrantCodes          map[string]types.GrantCode
	AccessTokens        map[string]types.Token
	RefreshTokens       map[string]types.Token
	isUserAuthenticated bool
}

func NewProvider(isUserAuthenticated bool) *Provider {
	p := &Provider{
		GrantCodes:    make(map[string]types.GrantCode),
		AccessTokens:  make(map[string]types.Token),
		RefreshTokens: make(map[string]types.Token),
	}

	p.isUserAuthenticated = isUserAuthenticated

	c := types.Client{
		ID:   "test_client_id",
		Name: "Test Client",
	}
	c.RedirectURL, _ = url.Parse("https://example.com/oauth2/callback")

	p.Client = c
	return p
}

func (p *Provider) ClientInfo(clientID string) (types.Client, error) {
	return p.Client, nil
}

func (p *Provider) GenGrantCode(client types.Client, scopes []types.Scope) (types.GrantCode, error) {
	a := types.GrantCode{
		Value:       uuid.NewV4().String(),
		ClientID:    client.ID,
		RedirectURL: client.RedirectURL,
		Scope:       scopes,
	}
	a.ExpiresIn = p.AuthzExpiration()

	p.GrantCodes[a.Value] = a
	return a, nil
}

func (p *Provider) RevokeGrantCode(code string) error {
	delete(p.GrantCodes, code)
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

func (p *Provider) GenToken(grantCode types.GrantCode, client types.Client, refreshToken bool) (types.Token, error) {
	t := types.Token{
		Value:    uuid.NewV4().String(),
		Type:     "bearer",
		Scope:    grantCode.Scope,
		ClientID: client.ID,
	}

	t.ExpiresIn = strconv.FormatFloat(p.TokenExpiration().Seconds(), 'f', -1, 64)
	if refreshToken {
		t.RefreshToken = uuid.NewV4().String()
		p.RefreshTokens[t.RefreshToken] = t
	}

	if v, ok := p.GrantCodes[grantCode.Value]; ok {
		v.IsUsed = true
		p.GrantCodes[grantCode.Value] = v
	}

	p.AccessTokens[t.Value] = t
	return t, nil
}

func (p *Provider) RevokeToken(token string) error {
	delete(p.AccessTokens, token)
	return nil
}

func (p *Provider) RefreshToken(refreshToken types.Token, scopes []types.Scope) (types.Token, error) {
	// Revokes existing refresh token
	delete(p.RefreshTokens, refreshToken.Value)

	grantCode := types.GrantCode{
		Scope: scopes,
	}

	return p.GenToken(grantCode, types.Client{
		ID: refreshToken.ClientID,
	}, true)
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

func (p *Provider) AuthenticateClient(username, password string) (types.Client, error) {
	if username == "boo" {
		c := types.Client{
			ID:   "boo",
			Name: "Boo",
		}
		c.RedirectURL, _ = url.Parse("https://example.com/oauth2/callback")
		return c, nil
	}
	return p.Client, nil
}

func (p *Provider) GrantInfo(client types.Client, code string) (types.GrantCode, error) {
	return p.GrantCodes[code], nil
}

func (p *Provider) TokenInfo(client types.Client, code string) (types.Token, error) {
	if v, ok := p.AccessTokens[code]; ok {
		return v, nil
	}

	return p.RefreshTokens[code], nil
}

func (p *Provider) AuthenticateUser(username, password string) bool {
	return true
}
