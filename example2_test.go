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

	authzForm := []byte("<html><h1>App ABC wants to access XYZ...</h1></html>")

	oauth2.SetSTSMaxAge(0)
	// Sets authorization HTML form
	oauth2.SetAuthzForm(authzForm)
	oauth2.SetProvider(nil)
	oauth2.SetTokenEndpoint(endpoint)
	oauth2.SetAuthzEndpoint(endpoint)
	oauth2.SetRevokeEndpoint(endpoint)

	log.Fatal(http.ListenAndServe(":3000", oauth2.Handler(mux)))
}
