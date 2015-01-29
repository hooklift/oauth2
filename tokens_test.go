package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hooklift/oauth2/types"
)

func AccessTokenRequest(t *testing.T, provider Provider, authzCode string) *http.Request {
	// http://tools.ietf.org/html/rfc6749#section-4.1.3
	queryStr := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authzCode},
		"redirect_uri": {},
		"client_id":    {""},
	}

	buffer := bytes.NewBufferString(queryStr.Encode())
	req, err := http.NewRequest("POST", "https://example.com/oauth2/tokens", buffer)
	ok(t, err)
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	return req
}

// TestAccessToken tests a happy path for getting access tokens in accordance with
// http://tools.ietf.org/html/rfc6749#section-4.1.3 and
// http://tools.ietf.org/html/rfc6749#section-4.1.4
func TestAccessTokenRequest(t *testing.T) {
	provider, authzCode := getTestAuthzCode(t)

	req := AccessTokenRequest(t, provider, authzCode)
	req.SetBasicAuth("testclient", "testclient")

	w := httptest.NewRecorder()
	IssueAccessToken(w, req, provider)

	// http://tools.ietf.org/html/rfc6749#section-4.1.4
	accessToken := types.Token{}
	err := json.Unmarshal(w.Body.Bytes(), &accessToken)
	ok(t, fmt.Errorf("%s -> %v", req.URL.String(), err))

	equals(t, "bearer", accessToken.Type)
	equals(t, 600, accessToken.ExpiresIn)
}

// TestClientAuthRequired tests that client is required to always authenticate in order
// to request access tokens.
func TestClientAuthRequired(t *testing.T) {

}

// TestAuthzCodeOwnership tests that the authorization code was issued to the client
// requesting the access token.
func TestAuthzCodeOwnership(t *testing.T) {

}
