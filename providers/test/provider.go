// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package test

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hooklift/oauth2/types"
	"github.com/satori/go.uuid"
)

type Provider struct {
	Client              types.Client
	Grants              map[string]types.Grant
	AccessTokens        map[string]types.Token
	RefreshTokens       map[string]types.Token
	isUserAuthenticated bool
}

func NewProvider(isUserAuthenticated bool) *Provider {
	p := &Provider{
		Grants:        make(map[string]types.Grant),
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

func (p *Provider) GenGrant(client types.Client, scopes types.Scopes, expiration time.Duration) (types.Grant, error) {
	a := types.Grant{
		Code:        uuid.NewV4().String(),
		ClientID:    client.ID,
		RedirectURL: client.RedirectURL,
		Scopes:      scopes,
	}
	a.ExpiresIn = time.Now().Add(expiration)

	p.Grants[a.Code] = a
	return a, nil
}

func (p *Provider) ScopesInfo(scopes string) (types.Scopes, error) {
	s := strings.Split(scopes, " ")
	scope := make(types.Scopes, 0)
	for _, v := range s {
		scope = append(scope, types.Scope{
			ID:          v,
			Description: "test scope",
		})
	}
	return scope, nil
}

func (p *Provider) GenToken(grant types.Grant, client types.Client, refreshToken bool, expiration time.Duration) (types.Token, error) {
	t := types.Token{
		Value:    uuid.NewV4().String(),
		Type:     "bearer",
		Scopes:   grant.Scopes,
		ClientID: client.ID,
	}

	t.ExpiresIn = strconv.FormatFloat(expiration.Seconds(), 'f', -1, 64)
	if refreshToken {
		t.RefreshToken = uuid.NewV4().String()
		p.RefreshTokens[t.RefreshToken] = t
	}

	if v, ok := p.Grants[grant.Code]; ok {
		v.Status = types.GrantUsed
		p.Grants[grant.Code] = v
	}

	p.AccessTokens[t.Value] = t
	return t, nil
}

func (p *Provider) RevokeToken(token string) error {
	delete(p.AccessTokens, token)
	delete(p.RefreshTokens, token)
	return nil
}

func (p *Provider) RefreshToken(refreshToken types.Token, scopes types.Scopes) (types.Token, error) {
	// Revokes existing refresh token
	delete(p.RefreshTokens, refreshToken.Value)

	grant := types.Grant{
		Scopes: scopes,
	}

	return p.GenToken(grant, types.Client{
		ID: refreshToken.ClientID,
	}, true, time.Duration(10)*time.Minute)
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

func (p *Provider) GrantInfo(code string) (types.Grant, error) {
	return p.Grants[code], nil
}

func (p *Provider) TokenInfo(code string) (types.Token, error) {
	if v, ok := p.AccessTokens[code]; ok {
		return v, nil
	}

	return p.RefreshTokens[code], nil
}

func (p *Provider) AuthenticateUser(username, password string) bool {
	return true
}

func (p *Provider) ResourceScopes(url *url.URL) (types.Scopes, error) {
	return types.Scopes{
		types.Scope{ID: "identity"},
		types.Scope{ID: "read"},
		types.Scope{ID: "write"},
	}, nil
}
