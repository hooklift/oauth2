package oauth2

import (
	"net/http"
	"net/url"
)

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var AuthzHandlers map[string]func(http.ResponseWriter, *http.Request, *config, http.Handler) = map[string]func(http.ResponseWriter, *http.Request, *config, http.Handler){
	"GET":    AuthzForm,
	"POST":   CreateGrant,
	"DELETE": RevokeGrant,
}

// AuthzForm implements http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.2.1
func AuthzForm(w http.ResponseWriter, req *http.Request, cfg *config, _ http.Handler) {
	// response_type
	// REQUIRED.  Value MUST be set to "code".Value MUST be set to "code".
	grantType := req.FormValue("response_type")

	// client_id
	// REQUIRED.  The client identifier as described in Section 2.2.
	clientID := req.FormValue("client_id")

	// redirect_uri
	// OPTIONAL.  As described in Section 3.1.2.
	redirectURI := req.FormValue("redirect_uri")

	// scope
	// OPTIONAL.  The scope of the access request as described by Section 3.3.
	scope := req.FormValue("scope")

	// RECOMMENDED.  An opaque value used by the client to maintain
	// state between the request and callback.  The authorization
	// server includes this value when redirecting the user-agent back
	// to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery as described in Section 10.12.
	state := req.FormValue("state")

	// The authorization server validates the request to ensure that all
	// required parameters are present and valid.
	if grantType != "code" && grantType != "token" {

	}

	if clientID == "" {

	}

	if scope != "" {

	}

	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err != nil {
			// If the request fails due to a missing, invalid, or mismatching
			// redirection URI, or if the client identifier is missing or invalid,
			// the authorization server SHOULD inform the resource owner of the
			// error and MUST NOT automatically redirect the user-agent to the
			// invalid redirection URI.
			//
			// TODO(c4milo): handle this error
			return
		}

		query := u.Query()
		query.Set("code", "the actual grantCode")
		query.Set("state", state)

		http.Redirect(w, req, u.String(), http.StatusMovedPermanently)
		return
	}
	w.Write(cfg.authzForm)
}

func CreateGrant(w http.ResponseWriter, req *http.Request, cfg *config, next http.Handler) {
}

// RevokeGrant invalidates all tokens issued with the given grant authorization code.
func RevokeGrant(w http.ResponseWriter, req *http.Request, cfg *config, next http.Handler) {

}

// AuthCodeGrant implements http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.2.1
func authCodeGrant1(w http.ResponseWriter, req *http.Request, cfg *config, next http.Handler) {
}

// ImplicitGrant implements http://tools.ietf.org/html/rfc6749#section-4.2
func implicitGrant(w http.ResponseWriter, req *http.Request, cfg *config, next http.Handler) {
}
