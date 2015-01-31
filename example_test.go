package oauth2

import (
	"log"
	"net/http"

	"github.com/hooklift/oauth2/providers/test"
)

func ExampleExamples() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hellow World!"))
	})

	provider := test.NewProvider(true)
	authzHandler := AuthzHandler(mux, provider)
	oauth2Handlers := Handler(authzHandler, provider)

	log.Fatal(http.ListenAndServe(":3000", oauth2Handlers))
}
