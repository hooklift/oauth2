package oauth2

import "net/http"

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var TokenHandlers map[string]func(http.ResponseWriter, *http.Request, Provider) = map[string]func(http.ResponseWriter, *http.Request, Provider){
	"POST": IssueAccessToken,
}

// Implements http://tools.ietf.org/html/rfc6749#section-4.1.3 and
// http://tools.ietf.org/html/rfc6749#section-4.1.4
func authCodeGrant2(w http.ResponseWriter, req *http.Request, provider Provider) {
}

// Implements http://tools.ietf.org/html/rfc6749#section-4.3
func resourceOwnerCredentialsGrant(w http.ResponseWriter, req *http.Request, provider Provider) {
}

// Implements http://tools.ietf.org/html/rfc6749#section-4.4
func clientCredentialsGrant(w http.ResponseWriter, req *http.Request, provider Provider) {
}

// Implements http://tools.ietf.org/html/rfc6749#section-5
func IssueAccessToken(w http.ResponseWriter, req *http.Request, provider Provider) {
}

// Implements http://tools.ietf.org/html/rfc6749#section-6
func refreshToken(w http.ResponseWriter, req *http.Request, provider Provider) {
}

// Implements https://tools.ietf.org/html/rfc7009
func revokeToken(w http.ResponseWriter, req *http.Request, provider Provider) {}
