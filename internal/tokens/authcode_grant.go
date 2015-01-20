package tokens

import "net/http"

// Implements http://tools.ietf.org/html/rfc6749#section-4.1.3 and
// http://tools.ietf.org/html/rfc6749#section-4.1.4
func authCodeGrant(w http.ResponseWriter, req *http.Request) {}
