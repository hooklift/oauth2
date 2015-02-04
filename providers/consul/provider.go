package consul

import (
	"net/url"

	"github.com/hashicorp/consul/consul"
	"github.com/hooklift/oauth2/types"
)

type Provider struct {
	consul *consul.Client
}

func NewProvider() *Provider {
	client, err := consul.NewClient(api.DefaultConfig())
	if err != nil {
		log.Fataln("[ERROR] Unable to connect to Consul: %v", err)
	}

	return &Provider{
		consul: client,
	}
}

func (p *Provider) AuthenticateClient(username, password string) (types.Client, error) {}
func (p *Provider) AuthenticateUser(username, password string) (valid bool)            {}
func (p *Provider) IsUserAuthenticated() bool                                          {}
func (p *Provider) ClientInfo(clientID string) (info types.Client, err error)          {}
func (p *Provider) GrantInfo(code string) (types.GrantCode, error)                     {}
func (p *Provider) TokenInfo(token string) (types.Token, error)                        {}
func (p *Provider) ScopesInfo(scopes string) ([]types.Scope, error)                    {}
func (p *Provider) ResourceScopes(url *url.URL) ([]types.Scope, error)                 {}
func (p *Provider) GenGrantCode(client types.Client, scopes []types.Scope) (code types.GrantCode, err error) {
}
func (p *Provider) GenToken(grantCode types.GrantCode, client types.Client, refreshToken bool) (token types.Token, err error) {
}
func (p *Provider) RevokeToken(token string) error {}
func (p *Provider) RefreshToken(refreshToken types.Token, scopes []types.Scope) (accessToken types.Token, err error) {
}
