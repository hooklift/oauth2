package oauth2

import (
	"log"
	"net/http"

	"github.com/hooklift/oauth2"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hellow World!"))
	})

	client := NewOAuth2Client("1234")

	authzForm := []byte("<html><h1>App ABC wants to access XYZ...</h1></html>")
	reqHandler := oauth2.Handler(
		mux,
		// Sets request context, this is use to check if there is a valid session or not
		// before displaying the authorization form to the resource owner.
		oauth2.SetTokenEndpoint("/oauth2/tokens"),
		oauth2.SetAuthzEndpoint("/oauth2/authzs"),
		oauth2.SetRevokeEndpoint("/oauth2/revoke"),
		// Disables Strict Transport Security for development purposes
		oauth2.SetSTSMaxAge(0),
		// Sets authorization HTML form
		oauth2.SetAuthzForm(authzForm),
		oauth2.SetProvider(nil),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
