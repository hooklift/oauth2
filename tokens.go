package oauth2

import (
	"net/http"
	"strings"

	"github.com/hooklift/oauth2/internal/render"
	"github.com/hooklift/oauth2/pkg"
	"github.com/hooklift/oauth2/types"
)

// TokenHandlers is a map to functions where each function handles a particular HTTP
// verb or method.
var TokenHandlers map[string]func(http.ResponseWriter, *http.Request, Provider) = map[string]func(http.ResponseWriter, *http.Request, Provider){
	"POST": IssueAccessToken,
}

// IssueAccessToken handles all requests going to tokens endpoint.
func IssueAccessToken(w http.ResponseWriter, req *http.Request, provider Provider) {
	username, password, ok := req.BasicAuth()
	cinfo, err := provider.AuthenticateClient(username, password)
	if !ok || err != nil {
		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   ErrUnauthorizedClient,
		})
		return
	}

	grantType := req.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		authCodeGrant2(w, req, provider, cinfo)
	case "client_credentials":
		clientCredentialsGrant(w, req, provider, cinfo)
	case "password":
		resourceOwnerCredentialsGrant(w, req, provider, cinfo)
	case "refresh_token":
		refreshToken(w, req, provider, cinfo)
	default:
		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   ErrUnsupportedGrantType,
		})
		return
	}
}

// Implements http://tools.ietf.org/html/rfc6749#section-4.1.3,
// http://tools.ietf.org/html/rfc6749#section-4.1.4 and
// http://tools.ietf.org/html/rfc6749#section-5.2
//
// Implementation notes:
//  * Ignores client_id as we are always requiring the client to authenticate
//  * Ignores redirect_uri as we force a static and pre-registered redirect URI for the client
func authCodeGrant2(w http.ResponseWriter, req *http.Request, provider Provider, cinfo types.Client) {
	code := req.FormValue("code")
	if code == "" {
		err := ErrUnauthorizedClient
		err.Desc = "Authorization code can't be empty."
		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   ErrUnauthorizedClient,
		})
		return
	}

	grantCode, err := provider.GrantInfo(code)
	if err != nil {
		e := ErrInvalidGrant
		e.Desc = err.Error()

		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   e,
		})
		return
	}

	if grantCode.IsRevoked || grantCode.IsExpired || grantCode.IsUsed {
		e := ErrInvalidGrant
		e.Desc = "Grant code was revoked, expired or already used."

		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   e,
		})
		return
	}

	if cinfo.RedirectURL.String() != grantCode.RedirectURL.String() {
		e := ErrInvalidGrant
		e.Desc = "Grant code was generated for a different redirect URI."

		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   e,
		})
		return
	}

	// This should not happen if the provider is doing its work properly but we are
	// checking anyways.
	if grantCode.ClientID != cinfo.ID {
		e := ErrInvalidGrant
		e.Desc = "Grant code was generated for a different client ID."

		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   e,
		})
		return
	}

	token, err := provider.GenToken(grantCode, cinfo, true)
	if err != nil {
		render.JSON(w, render.Options{
			Status: http.StatusInternalServerError,
			Data:   ErrServerError("", err),
		})
		return
	}

	render.JSON(w, render.Options{
		Status: http.StatusOK,
		Data:   token,
	})
}

// Implements http://tools.ietf.org/html/rfc6749#section-4.3
func resourceOwnerCredentialsGrant(w http.ResponseWriter, req *http.Request, provider Provider, cinfo types.Client) {
	if ok := provider.AuthenticateUser(req.FormValue("username"), req.FormValue("password")); !ok {
		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   ErrUnathorizedUser,
		})
		return
	}

	scope := req.FormValue("scope")
	var scopes []types.Scope
	if scope != "" {
		var err error
		scopes, err = provider.ScopesInfo(scope)
		if err != nil {
			render.JSON(w, render.Options{
				Status: http.StatusBadRequest,
				Data:   ErrServerError("", err),
			})
			return
		}
	}

	noAuthzGrant := types.GrantCode{
		Scope: scopes,
	}
	token, err := provider.GenToken(noAuthzGrant, cinfo, true)
	if err != nil {
		render.JSON(w, render.Options{
			Status: http.StatusInternalServerError,
			Data:   ErrServerError("", err),
		})
		return
	}

	render.JSON(w, render.Options{
		Status: http.StatusOK,
		Data:   token,
	})
}

// Implements http://tools.ietf.org/html/rfc6749#section-4.4
func clientCredentialsGrant(w http.ResponseWriter, req *http.Request, provider Provider, cinfo types.Client) {
	scope := req.FormValue("scope")
	var scopes []types.Scope
	if scope != "" {
		var err error
		scopes, err = provider.ScopesInfo(scope)
		if err != nil {
			render.JSON(w, render.Options{
				Status: http.StatusBadRequest,
				Data:   ErrServerError("", err),
			})
			return
		}
	}

	noAuthzGrant := types.GrantCode{
		Scope: scopes,
	}
	token, err := provider.GenToken(noAuthzGrant, cinfo, false)
	if err != nil {
		render.JSON(w, render.Options{
			Status: http.StatusInternalServerError,
			Data:   ErrServerError("", err),
		})
		return
	}

	render.JSON(w, render.Options{
		Status: http.StatusOK,
		Data:   token,
	})
}

// Implements http://tools.ietf.org/html/rfc6749#section-6
func refreshToken(w http.ResponseWriter, req *http.Request, provider Provider, cinfo types.Client) {
	code := req.FormValue("refresh_token")
	token, err := provider.TokenInfo(code)
	if err != nil {
		render.JSON(w, render.Options{
			Status: http.StatusInternalServerError,
			Data:   ErrServerError("", err),
		})
		return
	}

	scope := req.FormValue("scope")
	var scopes []types.Scope
	if scope != "" {
		var err error
		scopes, err = provider.ScopesInfo(scope)
		if err != nil {
			render.JSON(w, render.Options{
				Status: http.StatusInternalServerError,
				Data:   ErrServerError("", err),
			})
			return
		}

		// The requested scope MUST NOT include any scope not originally granted
		// by the resource owner, and if omitted is treated as equal to the scope
		// originally granted by the resource owner.
		tscopes := pkg.StringifyScopes(token.Scope)
		for _, s := range scopes {
			// TODO(c4milo): make more robust
			if !strings.Contains(tscopes, s.ID) {
				render.JSON(w, render.Options{
					Status: http.StatusBadRequest,
					Data:   ErrInvalidScope,
				})
				return
			}
		}
	}

	if len(scopes) == 0 {
		scopes = token.Scope
	}

	if token.ClientID != cinfo.ID {
		render.JSON(w, render.Options{
			Status: http.StatusBadRequest,
			Data:   ErrClientIDMismatch,
		})
		return
	}

	newToken, err := provider.RefreshToken(token, scopes)
	if err != nil {
		render.JSON(w, render.Options{
			Status: http.StatusInternalServerError,
			Data:   ErrServerError("", err),
		})
		return
	}

	render.JSON(w, render.Options{
		Status: http.StatusOK,
		Data:   newToken,
	})
}

// Implements https://tools.ietf.org/html/rfc7009
func revokeToken(w http.ResponseWriter, req *http.Request, provider Provider, cinfo types.Client) {}
