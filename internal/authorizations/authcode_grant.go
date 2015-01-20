package authorizations

import "net/http"

// Implements http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.1.2
func authCodeGrant(w http.ResponseWriter, req *http.Request) {}
