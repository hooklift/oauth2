// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package types defines oauth2 reusable types.
package types

import (
	"fmt"
	"net/url"
	"time"
)

// Client defines client information required by oauth2 to:
//   * Show an authorization form to a resource owner
//   * Validate that the provided request_uri parameter matches the one previously
//     registered for the client.
type Client struct {
	// Client's identifier.
	ID string
	// Client's name.
	Name string
	// Client's description.
	Description string
	// Logo image URL used when showing authorization form to resource owner.
	LogoURL *url.URL `db:"logo_url" json:"logo_url"`
	// Client's homepage URL to allow resource owners to verify client's authenticity by themselves.
	HomepageURL *url.URL `db:"homepage_url" json:"homepage_url"`
	// Redirect URL registered for this client.
	RedirectURL *url.URL `db:"redirect_url" json:"redirect_url"`
}

// Scope defines a type for manipulating OAuth2 scopes.
type Scope struct {
	// Scope's identifier. Example: read
	ID string
	// Scope's description
	Description string
}

// GrantStatus defines a type for possible statuses of an authorization grant.
type GrantStatus string

const (
	GrantRevoked GrantStatus = "revoked"
	GrantExpired             = "expired"
	GrantUsed                = "used"
)

// GrantCode represents an authorization grant code.
type GrantCode struct {
	// Authorization code value.
	Value string
	// Expiration time for this authorization code.
	ExpiresIn time.Duration `db:"expires_in" json:"expires_in"`
	// Client's identifier to which this code was emitted to.
	ClientID string `db:"client_id" json:"client_id"`
	// Redirect URL associated with the authorization code.
	RedirectURL *url.URL `db:"redirect_url" json:"redirect_url"`
	// List of authorization scopes for which this authorization code was generated.
	Scopes []Scope
	// The status of this authorization grant code
	Status GrantStatus `json:"-"`
}

// TokenStatus defines a type for possible statuses of an authorization grant.
type TokenStatus string

const (
	TokenExpired TokenStatus = "expired"
	TokenRevoked             = "revoked"
)

// Token represents an access token.
type Token struct {
	// client associated to this token
	ClientID string `db:"client_id" json:"-"`
	// The actual token value
	Value string `json:"access_token"`
	// Whether it is a bearer, MAC, SAML, etc
	Type string `json:"token_type"`
	// Expiration time for this token
	ExpiresIn string `db:"expires_in" json:"expires_in"`
	// Refresh token optionally emitted along with access token
	RefreshToken string `db:"refresh_token" json:"refresh_token,omitempty"`
	// Authorization scope allowed for this token
	Scopes []Scope `json:"-"`
	// The status of this token
	Status TokenStatus `json:"-"`
}

type AuthzError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (a *AuthzError) Error() string {
	str := fmt.Sprintf(`error="%s"`, a.Code)
	if a.Description != "" {
		str += fmt.Sprintf(`,error_description="%s"`, a.Description)
	}

	if a.URI != "" {
		str += fmt.Sprintf(`,error_uri="%s"`, a.URI)
	}
	return str
}
