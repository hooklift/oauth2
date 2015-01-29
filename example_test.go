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

	reqHandler := Handler(
		mux,
		test.NewProvider(true),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
