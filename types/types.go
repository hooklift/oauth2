package types

import (
	"net/url"
	"time"
)

// Client defines client information required by oauth2 to:
//   * Show an authorization form to a resource owner
//   * Validate that the provided request_uri parameter matches the one previously
//     registered for the client.
type Client struct {
	ID            string
	Name          string
	Desc          string
	ProfileImgURL *url.URL
	HomepageURL   *url.URL
	RedirectURL   *url.URL
}

// Scope defines a type for manipulating OAuth2 scopes.
type Scope struct {
	ID   string
	Desc string
}

// AuthzCode represents an authorization code
type AuthzCode struct {
	Code        string
	ExpiresIn   time.Duration
	ClientID    string
	RedirectURL *url.URL
	Scope       []Scope
}

// Token represents an access token.
type Token struct {
	ClientID  string
	Value     string
	Type      string // bearer only for now.
	ExpiresIn time.Duration
	Scope     []Scope
}

// TokenType defines a type for the two defined token types in OAuth2.
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)
