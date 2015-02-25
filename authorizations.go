// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package oauth2

import (
	"net/http"
	"net/url"

	"github.com/hooklift/oauth2/internal/render"
	"github.com/hooklift/oauth2/types"
)

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var AuthzHandlers map[string]func(http.ResponseWriter, *http.Request, config) = map[string]func(http.ResponseWriter, *http.Request, config){
	"GET":  CreateGrant,
	"POST": CreateGrant,
}

// AuthzData defines properties used to render the authorization form view
// that asks for authorization to the resource owner when using the web flow.
type AuthzData struct {
	// Client information.
	Client types.Client
	// Requested scope access from 3rd-party client
	Scopes types.Scopes
	// List of errors to display to the resource owner.
	Errors []types.AuthzError
	// Grant type is either "code" or "token" for implicit authorizations.
	GrantType string
	// State can be used to store CSRF tokens by the 3rd-party client app
	State string
}

// CreateGrant generates the authorization code for 3rd-party clients to use
// in order to get access and refresh tokens, asking the resource owner for authorization.
func CreateGrant(w http.ResponseWriter, req *http.Request, cfg config) {
	provider := cfg.provider
	if yes := provider.IsUserAuthenticated(); !yes {
		u := cfg.loginURL.url
		query := u.Query()
		query.Set(cfg.loginURL.redirectParam, req.URL.String())
		u.RawQuery = query.Encode()

		http.Redirect(w, req, u.String(), http.StatusFound)
		return
	}

	vars := []string{"client_id", "state", "redirect_uri", "scope", "response_type"}
	params := make(map[string]string)
	for _, v := range vars {
		// FormValue also parses query string if method is GET
		params[v] = req.FormValue(v)
	}

	authzData := authCodeGrant1(w, req, cfg, params)
	if authzData == nil {
		// A response with an error was already sent back
		return
	}

	if req.Method == "GET" {
		// Displays authorization form to resource owner in order for her to
		// authorize 3rd-party client app.
		// TODO(c4milo): Figure out how to generate a CSRF token not tied to user's session
		render.HTML(w, render.Options{
			Status:    http.StatusOK,
			Data:      authzData,
			Template:  cfg.authzForm,
			STSMaxAge: cfg.stsMaxAge,
		})
		return
	}

	if params["response_type"] == "token" {
		// Continue with implicit grant flow
		implicitGrant(w, req, cfg, authzData)
		return
	}

	// 4.1.2.  Authorization Response
	// If the resource owner grants the access request, the authorization
	// server issues an authorization code and delivers it to the client by
	// adding the following parameters to the query component of the
	// redirection URI using the "application/x-www-form-urlencoded" format,
	// per Appendix B:
	// http://tools.ietf.org/html/rfc6749#section-4.2.1
	grant, err := provider.GenGrant(authzData.Client, authzData.Scopes, cfg.authzExpiration)
	if err != nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzData{
				Errors: []types.AuthzError{
					ErrServerError("", err),
				}},
			Template: cfg.authzForm,
		})
		return
	}

	u := authzData.Client.RedirectURL
	query := u.Query()
	query.Set("code", grant.Code)
	query.Set("state", authzData.State)
	u.RawQuery = query.Encode()

	// log.Printf("[DEBUG] Redirect to: %s", u.String())
	http.Redirect(w, req, u.String(), http.StatusFound)
}

// AuthCodeGrant1 implements http://tools.ietf.org/html/rfc6749#section-4.1.1 and
// http://tools.ietf.org/html/rfc6749#section-4.2.1
func authCodeGrant1(w http.ResponseWriter, req *http.Request, cfg config, params map[string]string) *AuthzData {
	provider := cfg.provider
	// If the client identifier is missing or invalid, the authorization server
	// SHOULD inform the resource owner of the error and MUST NOT automatically
	// redirect the user-agent to the invalid redirection URI.
	clientID := params["client_id"]
	if clientID == "" {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzData{
				Errors: []types.AuthzError{
					ErrClientIDMissing,
				},
			},
			Template: cfg.authzForm,
		})
		return nil
	}

	cinfo, err := provider.ClientInfo(clientID)
	if err != nil {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzData{
				Errors: []types.AuthzError{
					ErrServerError("", err),
				},
			},
			Template: cfg.authzForm,
		})
		return nil
	}

	if cinfo == (types.Client{}) {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzData{
				Errors: []types.AuthzError{
					ErrClientIDNotFound,
				},
			},
			Template: cfg.authzForm,
		})
		return nil
	}

	// If the request fails due to a missing, invalid, or mismatching
	// redirection URI, the authorization server SHOULD inform the resource
	// owner of the error and MUST NOT automatically redirect the user-agent to the
	// invalid redirection URI.
	var redirectURL *url.URL
	if u, ok := params["redirect_uri"]; ok {
		var err error
		redirectURL, err = url.Parse(u)
		if err != nil {
			// We are deliberately avoiding sending client original parameters,
			// so the authorization process is forced to start all over again.
			render.HTML(w, render.Options{
				Status: http.StatusOK,
				Data: AuthzData{
					Errors: []types.AuthzError{
						ErrRedirectURLInvalid,
					},
				},
				Template: cfg.authzForm,
			})
			return nil
		}
	} else {
		redirectURL = cinfo.RedirectURL
	}

	if redirectURL.Scheme != "https" {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzData{
				Errors: []types.AuthzError{
					ErrRedirectURLInvalid,
				},
			},
			Template: cfg.authzForm,
		})
		return nil
	}

	// The authorization server MUST verify that the redirection URI to which
	// it will redirect the authorization code or access token matches a redirection URI registered
	// by the client as described in Section 3.1.2.
	if redirectURL.String() != cinfo.RedirectURL.String() {
		render.HTML(w, render.Options{
			Status: http.StatusOK,
			Data: AuthzData{
				Errors: []types.AuthzError{
					ErrRedirectURLMismatch,
				},
			},
			Template: cfg.authzForm,
		})
		return nil
	}

	// An opaque value used by the client to maintain state between the request
	// and callback.  The authorization server includes this value when redirecting
	// the user-agent back to the client.  The parameter SHOULD be used for preventing
	// cross-site request forgery as described in Section 10.12.
	state := params["state"]
	if state == "" {
		EncodeErrInURI(redirectURL, ErrStateRequired(state))
		http.Redirect(w, req, redirectURL.String(), http.StatusFound)
		return nil
	}

	// response_type
	// Value MUST be set to "code" or "token" for implicit authorizations.
	grantType := params["response_type"]
	if grantType != "code" && grantType != "token" {
		EncodeErrInURI(redirectURL, ErrUnsupportedResponseType(state))
		http.Redirect(w, req, redirectURL.String(), http.StatusFound)
		return nil
	}

	// The scope of the access request as described by Section 3.3.
	scope := params["scope"]
	if scope == "" {
		EncodeErrInURI(redirectURL, ErrScopeRequired(state))
		http.Redirect(w, req, redirectURL.String(), http.StatusFound)
		return nil
	}

	scopes, err := provider.ScopesInfo(scope)
	if err != nil {
		EncodeErrInURI(redirectURL, ErrServerError(state, err))
		http.Redirect(w, req, redirectURL.String(), http.StatusFound)
		return nil
	}

	return &AuthzData{
		Client:    cinfo,
		Scopes:    scopes,
		GrantType: grantType,
		State:     state,
	}
}

// ImplicitGrant implements http://tools.ietf.org/html/rfc6749#section-4.2
func implicitGrant(w http.ResponseWriter, req *http.Request, cfg config, authzData *AuthzData) {
	provider := cfg.provider
	u := authzData.Client.RedirectURL

	noAuthzGrant := types.Grant{
		Scopes: authzData.Scopes,
	}

	token, err := provider.GenToken(noAuthzGrant, authzData.Client, false, cfg.tokenExpiration)
	if err != nil {
		EncodeErrInURI(u, ErrServerError(authzData.State, err))
		http.Redirect(w, req, u.String(), http.StatusFound)
		return
	}

	query := url.Values{
		"access_token": {token.Value},
		"token_type":   {token.Type},
		"expires_in":   {token.ExpiresIn},
		"scope":        {token.Scopes.Encode()},
		"state":        {authzData.State},
	}

	u.Fragment = "#" + query.Encode()
	http.Redirect(w, req, u.String(), http.StatusFound)
}
