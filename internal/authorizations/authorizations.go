// Package authorizations handles requests for granting the following
// authorization grants, in accordance with http://tools.ietf.org/html/rfc6749:
//
// * Authorization Code
// * Implicit
// * Resource Owner Password Credentials
// * Client Credentials
package authorizations

import "net/http"

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var Handlers map[string]func(http.ResponseWriter, *http.Request) = map[string]func(http.ResponseWriter, *http.Request){
	"POST":   CreateGrant,
	"DELETE": RevokeGrant,
}

// Implements http://tools.ietf.org/html/rfc6749#section-4
func CreateGrant(w http.ResponseWriter, req *http.Request) {}

// Revoke blocks all associated tokens from making further requests.
func RevokeGrant(w http.ResponseWriter, req *http.Request) {}
