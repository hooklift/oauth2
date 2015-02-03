// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
