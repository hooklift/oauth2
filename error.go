package oauth2

import (
	"log"
	"net/url"
)

// Implements OAuth2 errors in accordance with:
// http://tools.ietf.org/html/rfc6749#section-4.1.2.1
// http://tools.ietf.org/html/rfc6749#section-4.2.2.1
// http://tools.ietf.org/html/rfc6749#section-5.2

type AuthzError struct {
	Code  string `json:"error"`
	Desc  string `json:"error_description"`
	URI   string `json:"error_uri,omitempty"`
	State string `json:"state,omitempty"`
}

func (a *AuthzError) Error() string {
	return a.Code
}

// Errors returned to resource owner in accordance with spec.
var (
	ErrRedirectURLMismatch = AuthzError{
		Code: "access_denied",
		Desc: "3rd-party client app provided a redirect_uri that does not match the URI registered for this client in our database.",
	}

	ErrRedirectURLInvalid = AuthzError{
		Code: "access_denied",
		Desc: "3rd-party client app provided an invalid redirect_uri. It does not comply with http://tools.ietf.org/html/rfc3986#section-4.3 or does not use HTTPS.",
	}

	ErrClientIDMissing = AuthzError{
		Code: "unauthorized_client",
		Desc: "3rd-party client app didn't send us its client ID.",
	}

	ErrClientIDNotFound = AuthzError{
		Code: "unauthorized_client",
		Desc: "3rd-party client app requesting access to your resources was not found in our database.",
	}

	ErrUnauthorizedClient = AuthzError{
		Code: "unauthorized_client",
		Desc: "You must provide an authorization header with your client credentials.",
	}

	ErrUnsupportedGrantType = AuthzError{
		Code: "unsupported_grant_type",
		Desc: "grant_type provided is not supported by this authorization server.",
	}

	ErrInvalidGrant = AuthzError{
		Code: "invalid_grant",
		Desc: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	}

	ErrUnathorizedUser = AuthzError{
		Code: "access_denied",
		Desc: "Resource owner credentials are invalid.",
	}

	ErrInvalidScope = AuthzError{
		Code: "invalid_scope",
		Desc: "Scope exceeds the scope granted by the resource owner.",
	}

	ErrClientIDMismatch = AuthzError{
		Code: "invalid_request",
		Desc: "Authenticated client did not generate refresh token used.",
	}
)

// Encodes errors as query string values in accordance to http://tools.ietf.org/html/rfc6749#section-4.1.2.1
func EncodeErrInURI(u *url.URL, err AuthzError) {
	queryStr := u.Query()
	queryStr.Set("error", err.Code)

	if err.Desc != "" {
		queryStr.Set("error_description", err.Desc)
	}

	if err.State != "" {
		queryStr.Set("state", err.State)
	}

	if err.URI != "" {
		queryStr.Set("error_uri", err.URI)
	}

	u.RawQuery = queryStr.Encode()
}

// Errors returned to 3rd-party client apps in accordance to spec.
func ErrUnsupportedResponseType(state string) AuthzError {
	return AuthzError{
		Code:  "unsupported_response_type",
		Desc:  "Authorization server does not support obtaining an authorization code using this authorization flow.",
		State: state,
	}
}

func ErrStateRequired(state string) AuthzError {
	return AuthzError{
		Code:  "invalid_request",
		Desc:  "state parameter is required by this authorization server.",
		State: state,
	}
}

func ErrScopeRequired(state string) AuthzError {
	return AuthzError{
		Code:  "invalid_request",
		Desc:  "scope parameter is required by this authorization server.",
		State: state,
	}
}

func ErrServerError(state string, err error) AuthzError {
	log.Printf("[ERROR] Internal server error: %v", err)

	return AuthzError{
		Code: "server_error",
		Desc: `The authorization server encountered an unexpected condition that
		prevented it from fulfilling the request.`,
		State: state,
	}
}
