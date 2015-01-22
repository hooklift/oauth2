package oauth2

import (
	"log"
	"net/http"

	"github.com/hooklift/oauth2"
)

// Implements oauth2.ClientManager
type OAuth2Client struct {
	oauth2.ClientInfo
}

func NewOAuth2Client(id string) *OAuth2Client {
	return &OAuth2Client{
		ID: id,
	}
}

func (c *OAuth2Client) Info() (oauth2.ClientInfo, error) {
	// Go to the datadabase to query client information
	return oauth2.ClientInfo{
		ID:          c.ID,
		Name:        "Acme Inc",
		Desc:        "Acme rulez",
		HomepageURL: "https://acme.com",
		RedirectURL: "https://acme.com/oauth2/callback",
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hellow World!"))
	})

	client := NewOAuth2Client("1234")

	authzForm := []byte("<html><h1>App ABC wants to access XYZ...</h1></html>")
	reqHandler := oauth2.Handler(
		mux,
		oauth2.SetTokenEndpoint("/oauth2/tokens"),
		oauth2.SetAuthzEndpoint("/oauth2/authzs"),
		oauth2.SetRevokeEndpoint("/oauth2/revoke"),
		// Disables Strict Transport Security for development purposes
		oauth2.SetSTSMaxAge(0),
		// Sets authorization html form
		oauth2.SetAuthzForm(authzForm),
		oauth2.SetClientManager(client),
		oauth2.SetAuthzCodeManager(client),
		oauth2.SetTokenManager(blah),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
