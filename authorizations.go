package oauth2

import (
	"net/http"
	"net/url"

	"github.com/hooklift/oauth2/internal/render"
)

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var AuthzHandlers map[string]func(http.ResponseWriter, *http.Request, *config, http.Handler) = map[string]func(http.ResponseWriter, *http.Request, *config, http.Handler){
	"GET":    AuthzForm,
	"POST":   CreateGrant,
	"DELETE": RevokeGrant,
}

// AuthzFormData defines properties used to render the authorization form view
// that asks for authorization to the resource owner when using the web flow.
type AuthzFormData struct {
	// Client information.
	Client Client
	// Requested scope access from 3rd-party client
	Scopes []Scope
	// List of errors to display to the resource owner.
	Errors []AuthzError
}

// AuthzForm implements OAuth2's web flow for confidential clients,
// specifically http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.2.1
func AuthzForm(w http.ResponseWriter, req *http.Request, cfg *config, _ http.Handler) {
	// An example of what a request reaching this function looks like:
	//  GET /oauth2/authzs?response_type=code&client_id=s6BhdRkqt3&state=xyz&
	//  redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
	//  Host: api.hooklift.io
	query := req.URL.Query()

	// response_type
	// REQUIRED.  Value MUST be set to "code".Value MUST be set to "code".
	grantType := query.Get("response_type")
	if grantType != "code" && grantType != "token" {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrUnsupportedResponseType(state),
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	// client_id
	// REQUIRED.  The client identifier as described in Section 2.2.
	clientID := query.Get("client_id")

	// If the client identifier is missing or invalid, the authorization server
	// SHOULD inform the resource owner of the error and MUST NOT automatically
	// redirect the user-agent to the invalid redirection URI.
	if clientID == "" {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrClientIDMissing(state),
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	cinfo, err := cfg.clientManager.ClientInfo(clientID)
	if err != nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrServerError(state, err),
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	if &cinfo == nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrClientIDNotFound(state),
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	// redirect_uri
	// OPTIONAL.  As described in Section 3.1.2.
	redirectURL := query.Get("redirect_uri")

	// If the request fails due to a missing, invalid, or mismatching
	// redirection URI, the authorization server SHOULD inform the resource
	// owner of the error and MUST NOT automatically redirect the user-agent to the
	// invalid redirection URI.
	if redirectURL == "" {
		redirectURL = cinfo.RedirectURL
	}

	if redirectURL != cinfo.RedirectURL {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrRedirectURLMismatch(state),
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	// RECOMMENDED.  An opaque value used by the client to maintain
	// state between the request and callback.  The authorization
	// server includes this value when redirecting the user-agent back
	// to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery as described in Section 10.12.
	state := query.Get("state")
	if state == "" {
		// TODO(c4milo): redirect to client callback URL with error
	}

	// scope
	// OPTIONAL.  The scope of the access request as described by Section 3.3.
	scope := query.Get("scope")
	if scope == "" {
		// TODO(c4milo): redirect user agent to client callback URL with access_denied error
	}

	scopes, err := cfg.scopeManager.ScopesInfo(scope)
	if err != nil {
		// TODO(c4milo): redirect user agent to client callback URL indicating an
		// internal server error
		return
	}

	formData := AuthzFormData{
		Client: cinfo,
		Scopes: scopes,
	}

	u, err := url.Parse(redirectURL)
	if err != nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrRedirectURLInvalid(state),
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	// query := u.Query()
	// query.Set("code", "the actual grantCode")
	// query.Set("state", state)

	http.Redirect(w, req, u.String(), http.StatusMovedPermanently)
	return

	// TODO(c4milo): Set security headers
	// Strict-Transport-Security
	// X-Frame-Options, Frame-Options
	// X-XSS-Protection
	// X-Content-Type-Options

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
