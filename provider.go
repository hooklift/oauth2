package oauth2

import (
	"net/http"
	"strings"

	"github.com/hooklift/oauth2/internal/authorizations"
	"github.com/hooklift/oauth2/internal/tokens"
)

// http://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html
type option func(*handler)

// Internal handler.
type handler struct {
	authEndpoint  string
	tokenEndpoint string
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
func TokenEndpoint(endpoint string) option {
	return func(h *handler) {
		h.tokenEndpoint = endpoint
	}
}

// AuthEndpoint allows setting authorization endpoint. Defaults to "/oauth2/authorizations"
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
func AuthEndpoint(endpoint string) option {
	return func(h *handler) {
		h.authEndpoint = endpoint
	}
}

// Handler handles OAuth2 requests.
func Handler(h http.Handler, opts ...option) http.Handler {
	// Default configuration options.
	handler := &handler{
		tokenEndpoint: "/oauth2/tokens",
		authEndpoint:  "/oauth2/authorizations",
	}

	// Applies user's configuration.
	for _, opt := range opts {
		opt(handler)
	}

	// Keeps a registry of path function handlers for OAuth2 requests.
	registry := map[string]map[string]func(http.ResponseWriter, *http.Request){
		handler.authEndpoint:  authorizations.Handlers,
		handler.tokenEndpoint: tokens.Handlers,
	}

	// Locates and runs specific OAuth2 handler for request's method
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for p, handlers := range registry {
			if strings.HasPrefix(req.URL.Path, p) {
				if handlerFn, ok := handlers[req.Method]; ok {
					handlerFn(w, req)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write([]byte("Method Not Allowed"))
				return
			}
		}
	})
}
