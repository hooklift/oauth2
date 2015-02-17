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

func (p *Provider) GenGrantCode(client types.Client, scopes []types.Scope, expiration time.Duration) (types.GrantCode, error) {
	a := types.GrantCode{
		Value:       uuid.NewV4().String(),
		ClientID:    client.ID,
		RedirectURL: client.RedirectURL,
		Scope:       scopes,
	}
	a.ExpiresIn = expiration

	p.GrantCodes[a.Value] = a
	return a, nil
}

func (p *Provider) ScopesInfo(scopes string) ([]types.Scope, error) {
	s := strings.Split(scopes, " ")
	scope := make([]types.Scope, 0)
	for _, v := range s {
		scope = append(scope, types.Scope{
			ID:          v,
			Description: "test scope",
		})
	}
	return scope, nil
}

func (p *Provider) GenToken(grantCode types.GrantCode, client types.Client, refreshToken bool, expiration time.Duration) (types.Token, error) {
	t := types.Token{
		Value:    uuid.NewV4().String(),
		Type:     "bearer",
		Scope:    grantCode.Scope,
		ClientID: client.ID,
	}

	t.ExpiresIn = strconv.FormatFloat(expiration.Seconds(), 'f', -1, 64)
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
	delete(p.RefreshTokens, token)
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

func (p *Provider) GrantInfo(code string) (types.GrantCode, error) {
	return p.GrantCodes[code], nil
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

func (p *Provider) ResourceScopes(url *url.URL) ([]types.Scope, error) {
	return []types.Scope{
		types.Scope{ID: "identity"},
		types.Scope{ID: "read"},
		types.Scope{ID: "write"},
	}, nil
}
