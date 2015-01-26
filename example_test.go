package oauth2

import (
	"log"
	"net/http"
	"time"

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
		oauth2.SetTokenEndpoint("/oauth2/tokens"),
		oauth2.SetAuthzEndpoint("/oauth2/authzs"),
		oauth2.SetRevokeEndpoint("/oauth2/revoke"),
		// When setting token expiration times, the lower they are the more
		// frequent your server is going to receive refresh tokens requests.
		// When the opposite is done, you will be widening the time window for
		// successful attacks. A reasonable value is 5 or 10 minutes.
		oauth2.SetTokenExpiration(time.Duration(5)*time.Minute),
		oauth2.SetAuthzExpiration(time.Duration(1)*time.Minute),
		// Disables Strict Transport Security for development purposes
		oauth2.SetSTSMaxAge(0),
		// Sets authorization HTML form
		oauth2.SetAuthzForm(authzForm),
		oauth2.SetProvider(nil),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
