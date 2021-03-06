// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package oauth2 implements the OAuth2 HTTP dancing in accordance with http://tools.ietf.org/html/rfc6749
// and leaves the rest of the implementation to its users by requiring them
// to implement oauth2.Provider interface.
package oauth2

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hooklift/oauth2/internal/render"
	"github.com/hooklift/oauth2/types"
)

// Provider defines functions required by the oauth2 package to properly work.
// Users of this package are required to implement them.
type Provider interface {
	// AuthenticateClient authenticates a previously registered client.
	AuthenticateClient(username, password string) (types.Client, error)

	// AuthenticateUser authenticates resource owner.
	AuthenticateUser(username, password string) (valid bool)

	// ClientInfo returns 3rd-party client information
	ClientInfo(clientID string) (info types.Client, err error)

	// GrantInfo returns information about the authorization grant code.
	GrantInfo(code string) (types.Grant, error)

	// TokenInfo returns information about one specific token.
	TokenInfo(token string) (types.Token, error)

	// ScopesInfo parses the list of scopes requested by the client and
	// returns its descriptions for the resource owner to fully understand
	// what she is authorizing the client to access to. An error is returned
	// if the scopes list does not comply with http://tools.ietf.org/html/rfc6749#section-3.3
	//
	// Unrecognized or non-existent scopes are ignored.
	ScopesInfo(scopes string) (types.Scopes, error)

	// ResourceScopes returns the scopes associated with a given resource
	ResourceScopes(url *url.URL) (types.Scopes, error)

	// GenGrant issues and stores an authorization grant code, in a persistent storage.
	// The authorization code MUST expire shortly after it is issued to mitigate
	// the risk of leaks.  A maximum authorization code lifetime of 10 minutes is
	// RECOMMENDED. If an authorization code is used more than once, the authorization
	// server MUST deny the request and SHOULD revoke (when possible) all tokens
	// previously issued based on that authorization code.  The authorization
	// code is bound to the client identifier and redirection URI.
	// -- http://tools.ietf.org/html/rfc6749#section-4.1.2
	GenGrant(client types.Client, scopes types.Scopes, expiration time.Duration) (code types.Grant, err error)

	// GenToken generates and stores access and refresh tokens with the given
	// client information and authorization scope.
	GenToken(grant types.Grant, client types.Client, refreshToken bool, expiration time.Duration) (token types.Token, err error)

	// RevokeToken expires a specific token.
	RevokeToken(token string) error

	// RefreshToken refreshes an access token.
	RefreshToken(refreshToken types.Token, scopes types.Scopes) (accessToken types.Token, err error)

	// IsUserAuthenticated checks whether or not the resource owner has a valid session
	// with the system. If not, it redirects the user to the login URL.
	IsUserAuthenticated() bool
}

// http://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
type option func(*config)

// Config defines the configuration struct for the oauth2 provider.
type config struct {
	authzEndpoint string
	tokenEndpoint string
	loginURL      struct {
		url           *url.URL
		redirectParam string
	}
	stsMaxAge       time.Duration
	authzForm       *template.Template
	provider        Provider
	authzExpiration time.Duration
	tokenExpiration time.Duration
}

// TokenEndpoint allows setting token endpoint. Defaults to "/oauth2/tokens".
//
// The token endpoint is used by the client to obtain an access token by
// presenting its authorization grant or refresh token.  The token
// endpoint is used with every authorization grant except for the
// implicit grant type (since an access token is issued directly).
//
// Since requests to the token endpoint result in the transmission of
// clear-text credentials (in the HTTP request and response), the
// authorization server MUST require the use of TLS as described in
// Section 1.6 when sending requests to the token endpoint.
//
// -- http://tools.ietf.org/html/rfc6749#section-3.2
func SetTokenEndpoint(endpoint string) option {
	return func(c *config) {
		c.tokenEndpoint = endpoint
	}
}

// AuthzEndpoint allows setting authorization endpoint. Defaults to "/oauth2/authzs"
//
// The authorization endpoint is used to interact with the resource owner and
// obtain an authorization grant.
//
// Since requests to the authorization endpoint result in user authentication
// and the transmission of clear-text credentials (in the HTTP response), the
// authorization server MUST require the use of TLS as described in Section 1.6
// when sending requests to the authorization endpoint.
//
// -- http://tools.ietf.org/html/rfc6749#section-3.1.1
func SetAuthzEndpoint(endpoint string) option {
	return func(c *config) {
		c.authzEndpoint = endpoint
	}
}

// SetSTSMaxAge sets Strict Transport Security maximum age. Defaults to 1yr.
func SetSTSMaxAge(maxAge time.Duration) option {
	return func(c *config) {
		c.stsMaxAge = maxAge
	}
}

// SetAuthzForm sets authorization form to show to the resource owner.
func SetAuthzForm(form string) option {
	return func(c *config) {
		t := template.New("authzform")
		tpl, err := t.Parse(form)
		if err != nil {
			log.Fatalf("Error parsing authorization form: %v", err)
		}

		c.authzForm = tpl
	}
}

// SetTokenExpiration allows setting expiration time for access tokens.
func SetTokenExpiration(e time.Duration) option {
	return func(c *config) {
		c.tokenExpiration = e
	}
}

// SetAuthzExpiration allows setting expiration time for authorization grant codes.
func SetAuthzExpiration(e time.Duration) option {
	return func(c *config) {
		c.authzExpiration = e
	}
}

// SetProvider sets backend provider
func SetProvider(p Provider) option {
	return func(c *config) {
		c.provider = p
	}
}

// SetLoginURL allows to set a login URL to redirect users to when they don't
// have valid sessions. The authentication system should send back the user
// to the referer URL in order to complete the OAuth2 authorization process.
func SetLoginURL(u, redirectParam string) option {
	loginURL, err := url.Parse(u)
	if err != nil {
		log.Fatalln("[ERROR] Invalid URL: %v", err)
	}

	return func(c *config) {
		c.loginURL.url = loginURL
		c.loginURL.redirectParam = redirectParam
	}
}

// AuthzHandler is intended to be used at the resource server side to protect and validate
// access to its resources. In accordance with http://tools.ietf.org/html/rfc6749#section-7
// and http://tools.ietf.org/html/rfc6750
func AuthzHandler(next http.Handler, provider Provider) http.Handler {
	if provider == nil {
		log.Fatalln("An implementation of the oauth2.Provider interface is expected")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var token string
		auth := req.Header.Get("Authorization")
		if auth == "" {
			token = req.FormValue("access_token")
		} else {
			if !strings.HasPrefix(auth, "Bearer ") {
				render.Unauthorized(w, render.Options{
					Status: http.StatusUnauthorized,
					Data:   ErrUnsupportedTokenType,
				})
				return
			}

			token = strings.TrimPrefix(auth, "Bearer ")
		}

		// If the request lacks any authentication information (e.g., the client
		// was unaware that authentication is necessary or attempted using an
		// unsupported authentication method), the resource server SHOULD NOT
		// include an error code or other error information.
		if token == "" {
			render.Unauthorized(w, render.Options{
				Status: http.StatusUnauthorized,
			})
			return
		}

		// Get token info from Authorizer
		tokenInfo, err := provider.TokenInfo(token)
		if err != nil {
			render.Unauthorized(w, render.Options{
				Status: http.StatusUnauthorized,
				Data:   ErrServerError("", err),
			})
			return
		}

		if tokenInfo.Status == types.TokenExpired || tokenInfo.Status == types.TokenRevoked {
			render.Unauthorized(w, render.Options{
				Status: http.StatusUnauthorized,
				Data:   ErrInvalidToken,
			})
			return
		}

		// Get scopes information for the given resource
		scopes, err := provider.ResourceScopes(req.URL)
		if err != nil {
			render.Unauthorized(w, render.Options{
				Status: http.StatusUnauthorized,
				Data:   ErrServerError("", err),
			})
			return
		}

		// Check that token's scope covers the requested resource
		resourceScopes := scopes.Encode()
		for _, scope := range tokenInfo.Scopes {
			if !strings.Contains(resourceScopes, scope.ID) {
				render.Unauthorized(w, render.Options{
					Status: http.StatusForbidden,
					Data:   ErrInsufficientScope,
				})
				return
			}
		}

		next.ServeHTTP(w, req)
	})
}

// Handler handles OAuth2 requests for getting authorization grants as well as
// access and refresh tokens.
func Handler(next http.Handler, opts ...option) http.Handler {
	// Default configuration options.
	cfg := config{
		tokenEndpoint: "/oauth2/tokens",
		authzEndpoint: "/oauth2/authzs",
		stsMaxAge:     time.Duration(31536000) * time.Second, // 1yr
	}

	// Applies user's configuration.
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.authzForm == nil {
		log.Fatalln("Authorization form is required")
	}

	if cfg.provider == nil {
		log.Fatalln("An implementation of the oauth2.Provider interface is expected")
	}

	// Keeps a registry of path function handlers for OAuth2 requests.
	registry := map[string]map[string]func(http.ResponseWriter, *http.Request, config){
		cfg.authzEndpoint: AuthzHandlers,
		cfg.tokenEndpoint: TokenHandlers,
	}

	// Locates and runs specific OAuth2 handler for request's method
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for p, handlers := range registry {
			if strings.HasPrefix(req.URL.Path, p) {
				if handlerFn, ok := handlers[req.Method]; ok {
					handlerFn(w, req, cfg)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write([]byte("Method Not Allowed"))
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}
