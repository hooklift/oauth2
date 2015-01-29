package oauth2

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hooklift/oauth2/providers/test"
	"github.com/hooklift/oauth2/types"
)

func AuthzGrantTokenRequestTest(t *testing.T, grantType, authzCode string) *http.Request {
	// http://tools.ietf.org/html/rfc6749#section-4.1.3
	queryStr := url.Values{
		"grant_type":   {grantType},
		"code":         {authzCode},
		"redirect_uri": {"https://example.com/oauth2/callback"},
		"client_id":    {"test_client_id"},
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
func TestAuthzGrantTokenRequest(t *testing.T) {
	provider, authzCode := getTestAuthzCode(t)

	req := AuthzGrantTokenRequestTest(t, "authorization_code", authzCode)
	req.SetBasicAuth("testclient", "testclient")

	w := httptest.NewRecorder()
	IssueAccessToken(w, req, provider)

	// http://tools.ietf.org/html/rfc6749#section-4.1.4
	accessToken := types.Token{}
	err := json.Unmarshal(w.Body.Bytes(), &accessToken)
	ok(t, err)

	//log.Printf("%s", w.Body.String())
	equals(t, "bearer", accessToken.Type)
	equals(t, "600", accessToken.ExpiresIn)
}

// TestClientAuthRequired tests that client is required to always authenticate in order
// to request access tokens.
func TestAuthzGrantClientAuthRequired(t *testing.T) {
	provider, authzCode := getTestAuthzCode(t)

	req := AuthzGrantTokenRequestTest(t, "authorization_code", authzCode)

	w := httptest.NewRecorder()
	IssueAccessToken(w, req, provider)
	// Tests for a 400 instead of 401 in accordance to http://tools.ietf.org/html/rfc6749#section-5.1
	equals(t, http.StatusBadRequest, w.Code)

	appErr := AuthzError{}
	err := json.Unmarshal(w.Body.Bytes(), &appErr)
	ok(t, err)
	equals(t, "unauthorized_client", appErr.Code)
}

// TestPasswordGrantTokenRequest tests happy path for http://tools.ietf.org/html/rfc6749#section-4.3
func TestResourceOwnerCredentialsTokenRequest(t *testing.T) {
	provider := test.NewProvider(true)
	queryStr := url.Values{
		"grant_type": {"password"},
		"username":   {"test_user"},
		"password":   {"test_password"},
	}

	buffer := bytes.NewBufferString(queryStr.Encode())
	req, err := http.NewRequest("POST", "https://example.com/oauth2/tokens", buffer)
	ok(t, err)
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("testclient", "testclient")

	w := httptest.NewRecorder()
	IssueAccessToken(w, req, provider)

	accessToken := types.Token{}
	err = json.Unmarshal(w.Body.Bytes(), &accessToken)
	ok(t, err)

	//log.Printf("%s", w.Body.String())
	equals(t, "bearer", accessToken.Type)
	equals(t, "600", accessToken.ExpiresIn)
}

// TestAuthzCodeOwnership tests that the authorization code was issued to the client
// requesting the access token.
func TestAuthzCodeOwnership(t *testing.T) {

}
