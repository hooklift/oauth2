package oauth2

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hooklift/oauth2/types"
)

// getAccessTokenTest is a helper function to generate a valid grant and an access token.
func getAccessTokenTest(t *testing.T) (Provider, types.Token) {
	provider, authzCode := getTestAuthzCode(t)

	req := AuthzGrantTokenRequestTest(t, "authorization_code", authzCode)
	req.SetBasicAuth("testclient", "testclient")

	w := httptest.NewRecorder()
	IssueToken(w, req, provider)

	token := types.Token{}
	err := json.Unmarshal(w.Body.Bytes(), &token)
	ok(t, err)
	return provider, token
}

// TestAuthzHandler tests that we are effectively able to protect server resources
// using AuthzHandler
func TestAuthzHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/protected_resource", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("success!"))
	}))

	provider, token := getAccessTokenTest(t)
	ts := httptest.NewServer(AuthzHandler(mux, provider))
	defer ts.Close()

	tests := []struct {
		url    string
		token  string
		status int
		body   string
		err    string
	}{
		{ts.URL, "", http.StatusUnauthorized, "", "invalid_token"},
		{ts.URL + "/protected_resource", token.Value, http.StatusOK, "success!", ""},
	}

	for _, tt := range tests {
		req, err := http.NewRequest("GET", tt.url, nil)
		ok(t, err)

		req.Header.Set("Authorization", "Bearer "+tt.token)
		res, err := http.DefaultClient.Do(req)
		ok(t, err)
		equals(t, tt.status, res.StatusCode)

		oauth2Err := res.Header.Get("WWW-Authenticate")
		equals(t, strings.Contains(oauth2Err, tt.err), true)

		body, err := ioutil.ReadAll(res.Body)
		ok(t, err)
		equals(t, tt.body, string(body[:]))
	}
}
