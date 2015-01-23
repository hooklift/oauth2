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

// Implements oauth2.TokenManager
type OAuth2Token struct{}

func (t *OAuth2Token) Generate(tokenType oauth2.TokenType, scope string) (string, err) {
	return "", nil
}

func (t *OAuth2Token) Revoke(token string) err {
	return "", nil
}

func (t *OAuth2Token) Refresh(refreshToken, scope string) (string, err) {
	return "", nil
}

// Implements oauth2.AuthzCodeManager
type OAuth2AuthzCode struct{}

func (t *OAuth2AuthzCode) Generate(clientID string) (string, err) {
	return "", nil
}

func (t *OAuth2AuthzCode) Revoke(code string) err {
	return "", nil
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
		// Sets authorization HTML form
		oauth2.SetAuthzForm(authzForm),
		oauth2.SetClientManager(client),
		oauth2.SetAuthzCodeManager(&OAuth2AuthzCode{}),
		oauth2.SetTokenManager(&OAuth2Token{}),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
