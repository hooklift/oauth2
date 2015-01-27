package oauth2

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"

	"testing"
)

// TestAuthorizationGrant tests a happy authorization grant flow
func TestAuthorizationGrant(t *testing.T) {
	cfg := &config{}
	provider := NewTestProvider()
	cfg.provider = provider

	state := "state-test"
	scopes := "read write identity"
	grantType := "code"

	values := url.Values{}
	values.Set("client_id", provider.client.ID)
	values.Set("response_type", grantType)
	values.Set("state", state)
	values.Set("redirect_uri", provider.client.RedirectURL.String())
	values.Set("scope", scopes)

	req, err := http.NewRequest("GET",
		"https://example.com/oauth2/authorize?"+values.Encode(), nil)
	if err != nil {
		log.Fatal(err)
	}

	w := httptest.NewRecorder()
	CreateGrant(w, req, cfg, nil)

	// Check that it returns authorization form with authzdata form included
	// Figure out how to generate a CSRF token not tied to user's session
	// send post request?

}

// TestImplicitGrant tests a happy implicit flow
func TestImplicitGrant(t *testing.T) {

}

// TestReplayAttackMitigation tests that the authorization grant can be used
// only once, and that if there are attempts to use it multiple times, it is
// revoked along with all the access tokens generated with it.
func TestReplayAttackMitigation(t *testing.T) {

}

// TestRedirectURLMatch makes sure redirect_uri for requesting an authorization
// grant is the same as the redirect_uri provided to get the correspondent access token.
// This is intended to mitigate the risk of account hijacking by leaking
// authorization codes.
func TestRedirectURLMatch(t *testing.T) {

}

// TestAccessTokenIssuer makes sure a token belongs to the client_id making
// the request with it. This mitigates account hijacking as well.
func TestAccessTokenOwnership(t *testing.T) {

}

// TestAccessTokenExpiration makes sure that access tokens are actually expired.
func TestAccessTokenExpiration(t *testing.T) {

}

// TestAuthzGrantExpiration makes sure that authorization codes are actually expired after used.
func TestAuthzGrantExpiration(t *testing.T) {

}

// TestScopeIsRequired makes sure it requires clients to provide access scopes.
func TestScopeIsRequired(t *testing.T) {

}

// TestStateIsRequired makes sure it requires clients to provide a state.
func TestStateIsRequired(t *testing.T) {

}

// TestSecurityHeaders makes sure security headers are sent along the authorization form.
func TestSecurityHeaders(t *testing.T) {

}

// TestRedirectURIScheme makes sure clients provide redirect URLs that use TLS
func TestRedirectURIScheme(t *testing.T) {

}

// TestRedirectURIUniqueness makes sure there is only one redirect URL registered across the system.
func TestRedirectURIUniqueness(t *testing.T) {

}

// TestStateParam makes sure the same state parameter value received to acquire
// the authorization grant is send back when delivering the access token.
func TestStateParam(t *testing.T) {

}
