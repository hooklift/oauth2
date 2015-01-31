// Package oauth2 implements the HTTP dancing in accordance with http://tools.ietf.org/html/rfc6749
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
	"github.com/hooklift/oauth2/pkg"
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
	GrantInfo(code string) (types.GrantCode, error)

	// TokenInfo returns information about one specific token.
	TokenInfo(token string) (types.Token, error)

	// ScopesInfo parses the list of scopes requested by the client and
	// returns its descriptions for the resource owner to fully understand
	// what he is authorizing the client to access to. An error is returned
	// if the scopes list does not comply with http://tools.ietf.org/html/rfc6749#section-3.3
	//
	// Unrecognized or non-existent scopes are ignored.
	ScopesInfo(scopes string) ([]types.Scope, error)

	// ResourceScopes returns the scopes associated with a given resource
	ResourceScopes(url *url.URL) ([]types.Scope, error)

	// GenGrantCode issues and stores an authorization grant code, in a persistent storage.
	// The authorization code MUST expire shortly after it is issued to mitigate
	// the risk of leaks.  A maximum authorization code lifetime of 10 minutes is
	// RECOMMENDED. If an authorization code is used more than once, the authorization
	// server MUST deny the request and SHOULD revoke (when possible) all tokens
	// previously issued based on that authorization code.  The authorization
	// code is bound to the client identifier and redirection URI.
	// -- http://tools.ietf.org/html/rfc6749#section-4.1.2
	GenGrantCode(client types.Client, scopes []types.Scope) (code types.GrantCode, err error)

	// GenToken generates and stores access and refresh tokens with the given
	// client information and authorization scope.
	GenToken(grantCode types.GrantCode, client types.Client, refreshToken bool) (token types.Token, err error)

	// RevokeToken expires a specific token.
	RevokeToken(token string) error

	// RefreshToken refreshes an access token.
	RefreshToken(refreshToken types.Token, scopes []types.Scope) (accessToken types.Token, err error)

	// AuthzForm returns the HTML authorization form.
	AuthzForm() *template.Template

	// LoginURL returns the login URL for the resource owner to authenticate if there is
	// not a valid session. The authentication system should send back the user
	// to the referer URL in order to complete the OAuth2 authorization process.
	LoginURL(refererURL string) (url string)

	// IsUserAuthenticated checks whether or not the resource owner has a valid session
	// with the system. If not, it redirects the user to the login URL.
	IsUserAuthenticated() bool

	// TokenEndpoint is used by the client to obtain an access token by
	// presenting its authorization grant or refresh token.  The token
	// endpoint is used with every authorization grant except for the
	// implicit grant type (since an access token is issued directly).
	//
	// -- http://tools.ietf.org/html/rfc6749#section-3.2
	TokenEndpoint() string

	// AuthzEndpoint the authorization endpoint is used to interact with the
	// resource owner and obtain an authorization grant.
	//
	// -- http://tools.ietf.org/html/rfc6749#section-3.1.1
	AuthzEndpoint() string

	// STSMaxAge returns a maximum age value for Strict Transport Security header
	STSMaxAge() time.Duration

	// TokenExpiration returns an expiration value for access tokens.
	// When setting token expiration times, the lower they are the more
	// frequent your server is going to receive refresh tokens requests.
	// When the opposite is done, you will be widening the time window for
	// successful attacks. A reasonable value is 5 or 10 minutes.
	TokenExpiration() time.Duration

	// AuthzExpiration returns an expiration value for authorization grant codes.
	// They should be ideally very low. For instance: 1 minute.
	AuthzExpiration() time.Duration
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

		if tokenInfo.IsExpired || tokenInfo.IsRevoked {
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
		resourceScopes := pkg.StringifyScopes(scopes)
		// log.Printf("[DEBUG] resource: %s", resourceScopes)
		// log.Printf("[DEBUG] requested: %s", pkg.StringifyScopes(tokenInfo.Scope))
		for _, scope := range tokenInfo.Scope {
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
func Handler(next http.Handler, provider Provider) http.Handler {
	if provider == nil {
		log.Fatalln("An implementation of the oauth2.Provider interface is expected")
	}

	// Keeps a registry of path function handlers for OAuth2 requests.
	registry := map[string]map[string]func(http.ResponseWriter, *http.Request, Provider){
		provider.AuthzEndpoint(): AuthzHandlers,
		provider.TokenEndpoint(): TokenHandlers,
	}

	// Locates and runs specific OAuth2 handler for request's method
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for p, handlers := range registry {
			if strings.HasPrefix(req.URL.Path, p) {
				if handlerFn, ok := handlers[req.Method]; ok {
					handlerFn(w, req, provider)
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
