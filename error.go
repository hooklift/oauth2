package oauth2

import "log"

// OAuth2 errors in accordance with:
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

func ErrRedirectURLMismatch(state string) AuthzError {
	return AuthzError{
		Code:  "invalid_request",
		Desc:  "redirect_uri does not match the URI registered for the client.",
		State: state,
	}
}

func ErrRedirectURLInvalid(state string) AuthzError {
	return AuthzError{
		Code:  "invalid_request",
		Desc:  "redirect_uri does not comply with http://tools.ietf.org/html/rfc3986#section-4.3",
		State: state,
	}
}

func ErrUnsupportedResponseType(state string) AuthzError {
	return AuthzError{
		Code:  "unsupported_response_type",
		Desc:  "Authorization server does not support obtaining an authorization code using this authorization flow.",
		State: state,
	}
}

func ErrClientIDMissing(state string) AuthzError {
	return AuthzError{
		Code:  "unauthorized_client",
		Desc:  "client_id request parameter is missing.",
		State: state,
	}
}

func ErrClientIDNotFound(state string) AuthzError {
	return AuthzError{
		Code:  "unauthorized_client",
		Desc:  "client_id provided was not found.",
		State: state,
	}
}

// The authorization server encountered an unexpected
// condition that prevented it from fulfilling the request.
func ErrServerError(state string, err error) AuthzError {
	log.Printf("[ERROR] Internal server error: %v", err)

	return AuthzError{
		Code: "server_error",
		Desc: `The authorization server encountered an unexpected condition that
		prevented it from fulfilling the request.`,
		State: state,
	}
}
