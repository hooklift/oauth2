// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package oauth2

import (
	"log"
	"net/url"

	"github.com/hooklift/oauth2/types"
)

// Implements OAuth2 errors in accordance with:
// http://tools.ietf.org/html/rfc6749#section-4.1.2.1
// http://tools.ietf.org/html/rfc6749#section-4.2.2.1
// http://tools.ietf.org/html/rfc6749#section-5.2

// Errors returned to resource owner in accordance with spec.
var (
	ErrRedirectURLMismatch = types.AuthzError{
		Code:        "access_denied",
		Description: "3rd-party client app provided a redirect_uri that does not match the URI registered for this client in our database.",
	}

	ErrRedirectURLInvalid = types.AuthzError{
		Code:        "access_denied",
		Description: "3rd-party client app provided an invalid redirect_uri. It does not comply with http://tools.ietf.org/html/rfc3986#section-4.3 or does not use HTTPS.",
	}

	ErrClientIDMissing = types.AuthzError{
		Code:        "unauthorized_client",
		Description: "3rd-party client app didn't send us its client ID.",
	}

	ErrClientIDNotFound = types.AuthzError{
		Code:        "unauthorized_client",
		Description: "3rd-party client app requesting access to your resources was not found in our database.",
	}

	ErrUnauthorizedClient = types.AuthzError{
		Code:        "unauthorized_client",
		Description: "You must provide an authorization header with your client credentials.",
	}

	ErrUnsupportedGrantType = types.AuthzError{
		Code:        "unsupported_grant_type",
		Description: "grant_type provided is not supported by this authorization server.",
	}

	ErrInvalidGrant = types.AuthzError{
		Code:        "invalid_grant",
		Description: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
	}

	ErrUnathorizedUser = types.AuthzError{
		Code:        "access_denied",
		Description: "Resource owner credentials are invalid.",
	}

	ErrInvalidScope = types.AuthzError{
		Code:        "invalid_scope",
		Description: "Scope exceeds the scope granted by the resource owner.",
	}

	ErrClientIDMismatch = types.AuthzError{
		Code:        "invalid_request",
		Description: "Authenticated client did not generate token used.",
	}

	ErrUnsupportedTokenType = types.AuthzError{
		Code:        "invalid_token",
		Description: "Unsupported token type.",
	}

	ErrAccessTokenRequired = types.AuthzError{
		Code:        "invalid_request",
		Description: "An access token is required to access this resource.",
	}

	ErrInvalidToken = types.AuthzError{
		Code:        "invalid_token",
		Description: "Access token expired or was revoked.",
	}

	ErrInsufficientScope = types.AuthzError{
		Code:        "insufficient_scope",
		Description: "The request requires higher privileges than provided by the access token.",
	}
)

// Encodes errors as query string values in accordance to http://tools.ietf.org/html/rfc6749#section-4.1.2.1
func EncodeErrInURI(u *url.URL, err types.AuthzError) {
	queryStr := u.Query()
	queryStr.Set("error", err.Code)

	if err.Description != "" {
		queryStr.Set("error_description", err.Description)
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
func ErrUnsupportedResponseType(state string) types.AuthzError {
	return types.AuthzError{
		Code:        "unsupported_response_type",
		Description: "Authorization server does not support obtaining an authorization code using this authorization flow.",
		State:       state,
	}
}

func ErrStateRequired(state string) types.AuthzError {
	return types.AuthzError{
		Code:        "invalid_request",
		Description: "state parameter is required by this authorization server.",
		State:       state,
	}
}

func ErrScopeRequired(state string) types.AuthzError {
	return types.AuthzError{
		Code:        "invalid_request",
		Description: "scope parameter is required by this authorization server.",
		State:       state,
	}
}

func ErrServerError(state string, err error) types.AuthzError {
	log.Printf("[ERROR] Internal server error: %v", err)

	return types.AuthzError{
		Code: "server_error",
		Description: `The authorization server encountered an unexpected condition that
		prevented it from fulfilling the request.`,
		State: state,
	}
}
