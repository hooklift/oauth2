package oauth2

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hooklift/oauth2/types"
)

func getAccessTokenTest(t *testing.T) (Provider, types.Token) {
	provider, authzCode := getTestAuthzCode(t)

	req := AuthzGrantTokenRequestTest(t, "authorization_code", authzCode)
	req.SetBasicAuth("testclient", "testclient")

	w := httptest.NewRecorder()
	IssueAccessToken(w, req, provider)

	token := types.Token{}
	err := json.Unmarshal(w.Body.Bytes(), &token)
	ok(t, err)
	return provider, token
}

func TestAuthzHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/protected_resource", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("success!"))
	}))

	provider, token := getAccessTokenTest(t)
	ts := httptest.NewServer(AuthzHandler(mux, provider))
	defer ts.Close()

	r1, err := http.NewRequest("GET", ts.URL, nil)
	ok(t, err)

	res1, err := http.DefaultClient.Do(r1)
	ok(t, err)
	equals(t, res1.StatusCode, http.StatusUnauthorized)

	r2, err := http.NewRequest("GET", ts.URL+"/protected_resource", nil)
	ok(t, err)

	r2.Header.Set("Authorization", "Bearer "+token.Value)
	res2, err := http.DefaultClient.Do(r2)
	ok(t, err)

	log.Printf("%s", res2.Header.Get("Www-Authenticate"))
	equals(t, res2.StatusCode, http.StatusOK)
	data, err := ioutil.ReadAll(res2.Body)
	ok(t, err)
	equals(t, string(data[:]), "success!")
}
