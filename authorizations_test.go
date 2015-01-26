package oauth2

import "testing"

// TestAuthorizationGrant tests a happy authorization grant flow
func TestAuthorizationGrant(t *testing.T) {

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
