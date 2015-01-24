package oauth2

import (
	"net/http"
	"net/url"

	"github.com/hooklift/oauth2/internal/render"
)

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var AuthzHandlers map[string]func(http.ResponseWriter, *http.Request, *config) = map[string]func(http.ResponseWriter, *http.Request, *config){
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
	// Grant type is either "code" or "token" for implicit authorizations.
	GrantType string
	// State is an anti CSRF token sent by the 3rd-party client app
	State string
}

// AuthzForm implements OAuth2's web flow for confidential clients,
// specifically http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.2.1
func AuthzForm(w http.ResponseWriter, req *http.Request, cfg *config) {
	// An example of what a request reaching this function looks like:
	//  GET /oauth2/authzs?response_type=code&client_id=s6BhdRkqt3&state=xyz&
	//  redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
	//  Host: api.hooklift.io

	if invalid := cfg.provider.CheckSession(); invalid {
		loginURL := cfg.provider.LoginURL(req.URL.String())
		http.Redirect(w, req, loginURL, http.StatusFound)
		return
	}

	query := req.URL.Query()

	// The client identifier as described in Section 2.2.
	clientID := query.Get("client_id")

	// If the client identifier is missing or invalid, the authorization server
	// SHOULD inform the resource owner of the error and MUST NOT automatically
	// redirect the user-agent to the invalid redirection URI.
	if clientID == "" {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrClientIDMissing,
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	cinfo, err := cfg.provider.ClientInfo(clientID)
	if err != nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrServerError("", err),
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
					ErrClientIDNotFound,
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	// As described in Section 3.1.2.
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
					ErrRedirectURLMismatch,
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	u, err := url.Parse(redirectURL)
	if err != nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzFormData{
				Errors: []AuthzError{
					ErrRedirectURLInvalid,
				},
			},
			Template: cfg.authzForm,
		})
		return
	}

	// An opaque value used by the client to maintain state between the request
	// and callback.  The authorization server includes this value when redirecting
	// the user-agent back to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery as described in Section 10.12.
	state := query.Get("state")
	if state == "" {
		EncodeErrInURI(u.Query(), ErrStateRequired(state))
		http.Redirect(w, req, u.String(), http.StatusFound)
	}

	// response_type
	// Value MUST be set to "code" or "token" for implicit authorizations.
	grantType := query.Get("response_type")
	if grantType != "code" && grantType != "token" {
		EncodeErrInURI(u.Query(), ErrUnsupportedResponseType(state))
		http.Redirect(w, req, u.String(), http.StatusFound)
		return
	}

	// The scope of the access request as described by Section 3.3.
	scope := query.Get("scope")
	if scope == "" {
		EncodeErrInURI(u.Query(), ErrScopeRequired(state))
		http.Redirect(w, req, u.String(), http.StatusFound)
		return
	}

	scopes, err := cfg.provider.ScopesInfo(scope)
	if err != nil {
		EncodeErrInURI(u.Query(), ErrServerError(state, err))
		http.Redirect(w, req, u.String(), http.StatusFound)
		return
	}

	formData := AuthzFormData{
		Client:    cinfo,
		Scopes:    scopes,
		GrantType: grantType,
		State:     state,
	}

	render.HTML(w, render.Options{
		Status:    http.StatusOK,
		Data:      formData,
		Template:  cfg.authzForm,
		STSMaxAge: cfg.stsMaxAge,
	})
}

func CreateGrant(w http.ResponseWriter, req *http.Request, cfg *config) {

}

// RevokeGrant invalidates all tokens issued with the given grant authorization code.
func RevokeGrant(w http.ResponseWriter, req *http.Request, cfg *config) {

}

// AuthCodeGrant implements http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.2.1
func authCodeGrant1(w http.ResponseWriter, req *http.Request, cfg *config) {
}

// ImplicitGrant implements http://tools.ietf.org/html/rfc6749#section-4.2
func implicitGrant(w http.ResponseWriter, req *http.Request, cfg *config) {
}
