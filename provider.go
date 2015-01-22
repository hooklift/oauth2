// Package oauth2 implements an OAuth 2.0 authorization server with support
// for JWT tokens as well as token revokation.
//
// For details about the specs implemented please refer to
// * http://tools.ietf.org/html/rfc6749
// * http://tools.ietf.org/html/rfc6750
// * https://tools.ietf.org/html/rfc7009
// * https://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-22 (TODO)
// * https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
// * https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
package oauth2

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// Defines client information required by oauth2 to:
//   * Show an authorization form to a resource owner
//   * Validate that the provided request_uri parameter matches the one previously
//     registered for the client.
type ClientInfo struct {
	ID            string
	Name          string
	Desc          string
	ProfileImgURL string
	HomepageURL   string
	RedirectURL   string
}

// Defines the contract for getting oauth2 client information needed to
// make oauth2 validations.
type ClientManager interface {
	// Client information pre-registered by the third-party integrator
	ClientInfo(clientID string) (info ClientInfo, err error)
}

// AuthzCodeManager defines the contract for generating and storing authorization grants that are
// going to be sent to clients.
type AuthzCodeManager interface {
	// Generates and Stores an authorization grant code, in a persistent storage.
	Generate(grantCode string) error
	// Expires the grant code as well as all access and refresh tokens generated with it.
	Revoke(grantCode string) error
}

// Defines a type for the two defined token types in OAuth2.
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

type TokenManager interface {
	// Generates and stores token.
	Generate(tokenType TokenType, scope string) (token string, err error)

	// Expires a specific token.
	Revoke(token string) error

	// Refreshes an access token
	Refresh(refreshToken, scope string) (accessToken string, err error)
}

// http://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
type option func(*config)

// Internal handler.
type config struct {
	authzEndpoint    string
	tokenEndpoint    string
	revokeEndpoint   string
	stsMaxAge        time.Duration
	authzForm        []byte
	clientManager    ClientManager
	authzCodeManager AuthzCodeManager
	tokenManager     TokenManager
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

// RevokeEndpoint allows revoking tokens in accordance with https://tools.ietf.org/html/rfc7009
// Defaults to "/oauth2/revoke"
func SetRevokeEndpoint(endpoint string) option {
	return func(c *config) {
		c.revokeEndpoint = endpoint
	}
}

// Sets Strict Transport Security maximum age. Defaults to 1yr
func SetSTSMaxAge(maxAge time.Duration) option {
	return func(c *config) {
		c.stsMaxAge = maxAge
	}
}

// Authorization form to show to the resource owner
func SetAuthzForm(form []byte) option {
	return func(c *config) {
		c.authzForm = form
	}
}

// Sets ClientManager implementation to use when authorizing oauth2 clients
func SetClientManager(cm ClientManager) option {
	return func(c *config) {
		c.clientManager = cm
	}
}

// Sets AuthzGrantManager implementation to use when generating or revoking
// grant codes.
func SetAuthzCodeManager(agm AuthzCodeManager) option {
	return func(c *config) {
		c.authzCodeManager = agm
	}
}

// Sets TokenManager implementation to use when generating or revoking
// access or refresh token.
func SetTokenManager(tm TokenManager) option {
	return func(c *config) {
		c.tokenManager = tm
	}
}

// Handler handles OAuth2 requests.
func Handler(next http.Handler, opts ...option) http.Handler {
	// Default configuration options.
	cfg := &config{
		tokenEndpoint:  "/oauth2/tokens",
		authzEndpoint:  "/oauth2/authzs",
		revokeEndpoint: "/oauth2/revoke",
	}

	cfg.stsMaxAge = time.Duration(31536000) * time.Second // 1yr

	// Applies user's configuration.
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.authzForm == nil {
		log.Fatalln("Authorization form is required")
	}

	if cfg.clientManager == nil {
		log.Fatalln("An implementation of the oauth2.ClientManager interface is expected")
	}

	// Keeps a registry of path function handlers for OAuth2 requests.
	registry := map[string]map[string]func(http.ResponseWriter, *http.Request, *config, http.Handler){
		cfg.authzEndpoint: AuthzHandlers,
		cfg.tokenEndpoint: TokenHandlers,
		// TODO(c4milo): handlers for revoking tokens and grants
	}

	// Locates and runs specific OAuth2 handler for request's method
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for p, handlers := range registry {
			if strings.HasPrefix(req.URL.Path, p) {
				if handlerFn, ok := handlers[req.Method]; ok {
					handlerFn(w, req, cfg, next)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write([]byte("Method Not Allowed"))
				return
			}
		}
	})
}
