package oauth2

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func setup() {

}

// TestAuthorizationGrant tests a happy authorization grant flow in accordance with
// http://tools.ietf.org/html/rfc6749#section-4.1
func TestAuthorizationGrant(t *testing.T) {
	provider := NewTestProvider()
	tpl := `
		<html>
		<body>
		{{if .Errors}}
			<div id="errors">
				<ul>
				{{range .Errors}}
					<li>{{.Code}}: {{.Desc}}</li>
				{{end}}
				</ul>
			</div>
		{{else}}
			<form>
			 <input type="hidden" name="client_id" value="{{.Client.ID}}"/>
			 <input type="hidden" name="response_type" value="{{.GrantType}}"/>
			 <input type="hidden" name="redirect_uri" value="{{.Client.RedirectURL}}"/>
			 <input type="hidden" name="scope" value="{{StringifyScopes .Scopes}}"/>
			 <input type="hidden" name="state" value="{{.State}}"/>
			</form>
		{{end}}
		</body>
		</html>
	`

	cfg := &config{
		tokenEndpoint:  "/oauth2/tokens",
		authzEndpoint:  "/oauth2/authzs",
		revokeEndpoint: "/oauth2/revoke",
	}

	SetProvider(NewTestProvider())(cfg)
	SetAuthzForm(tpl)(cfg)

	state := "state-test"
	scopes := "read write identity"
	grantType := "code"

	values := url.Values{
		"client_id":     {provider.client.ID},
		"response_type": {grantType},
		"state":         {state},
		"redirect_uri":  {provider.client.RedirectURL.String()},
		"scope":         {scopes},
	}

	// http://tools.ietf.org/html/rfc6749#section-4.1.1
	queryStr := values.Encode()
	req, err := http.NewRequest("GET",
		"https://example.com/oauth2/authzs?"+queryStr, nil)
	ok(t, err)

	w := httptest.NewRecorder()
	CreateGrant(w, req, cfg, nil)
	statusCode := w.Code
	assert(t, statusCode == http.StatusOK, "Does not look like we got a 200 status code: %d", statusCode)

	body := w.Body.String()
	stringz := []string{
		"client_id",
		"redirect_uri",
		"response_type",
		"state",
		"scope",
		"code",
		"read write identity",
		"state-test",
	}

	for _, s := range stringz {
		assert(t, strings.Contains(body, s), "Does not look like we got an authorization form: '%s' was not found in %v", s, body)
	}

	// Sending post to acquire authorization token
	buffer := bytes.NewBufferString(queryStr)
	req, err = http.NewRequest("POST", "https://example.com/oauth2/authzs", buffer)
	ok(t, err)

	req.Header.Set("Content-type", "application/x-www-form-urlencoded")

	w = httptest.NewRecorder()
	CreateGrant(w, req, cfg, nil)

	// Tests http://tools.ietf.org/html/rfc6749#section-4.1.2
	equals(t, http.StatusFound, w.Code)

	redirectTo := w.Header().Get("Location")
	url, err := url.Parse(redirectTo)
	ok(t, err)

	authzCode := url.Query().Get("code")
	assert(t, authzCode != "", "It looks like the authorization code came back empty: %s", authzCode)
	equals(t, state, url.Query().Get("state"))
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
