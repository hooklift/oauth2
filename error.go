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
	URI   string `json:"error_uri"`
	State string `json:"state"`
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
)

// Encodes errors as query string values in accordance to http://tools.ietf.org/html/rfc6749#section-4.1.2.1
func EncodeErrInURI(u url.Values, err AuthzError) {
	u.Set("error", err.Code)

	if err.Desc != "" {
		u.Set("error_description", err.Desc)
	}

	if err.State != "" {
		u.Set("state", err.State)
	}

	if err.URI != "" {
		u.Set("error_uri", err.URI)
	}
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
		Code:  "access_denied",
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
