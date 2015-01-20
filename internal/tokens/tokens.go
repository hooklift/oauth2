// Package tokens handles requests for issuing and refreshing access and
// refresh tokens in accordance with http://tools.ietf.org/html/rfc6749
package tokens

import "net/http"

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var Handlers map[string]func(http.ResponseWriter, *http.Request) = map[string]func(http.ResponseWriter, *http.Request){
	"POST": GenerateOrRefreshOrRevoke,
}

// Implements http://tools.ietf.org/html/rfc6749#section-5
func GenerateOrRefreshOrRevoke(w http.ResponseWriter, req *http.Request) {}

// Implements http://tools.ietf.org/html/rfc6749#section-6
func refreshToken(w http.ResponseWriter, req *http.Request) {}

// Implements https://tools.ietf.org/html/rfc7009
func revokeToken(w http.ResponseWriter, req *http.Request) {}
