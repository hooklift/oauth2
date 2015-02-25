// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package oauth2

import (
	"log"
	"net/http"
	"time"

	"github.com/hooklift/oauth2/providers/test"
)

func ExampleExamples_basic() {
	// Authorization form
	authzForm := `
		<html>
		<body>
		{{if .Errors}}
			<div id="errors">
				<ul>
				{{range .Errors}}
					<li>{{.Code}}: {{.Desc}}</li>
				{{end}}
				</ul>
			</div>
		{{else}}
			<div id="client">
				<h2>{{.Client.Name}}</h2>
				<h3>{{.Client.Desc}}</h3>
				<a href="{{.Client.HomepageURL}}">
					<figure><img src="{{.Client.ProfileImgURL}}"/></figure>
				</a>
			</div>
			<div id="scopes">
				<ul>
					{{range .Scopes}}
						<li>{{.ID}}: {{.Desc}}</li>
					{{end}}
				</ul>
			</div>
			<form>
			 <input type="hidden" name="client_id" value="{{.Client.ID}}"/>
			 <input type="hidden" name="response_type" value="{{.GrantType}}"/>
			 <input type="hidden" name="redirect_uri" value="{{.Client.RedirectURL}}"/>
			 <input type="hidden" name="scope" value="{{.Scopes.Encode}}"/>
			 <input type="hidden" name="state" value="{{.State}}"/>
			</form>
		{{end}}
		</body>
		</html>
	`

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hellow World!"))
	})

	provider := test.NewProvider(true)
	// Authorization handler to protect resources in this server
	authzHandler := AuthzHandler(mux, provider)
	// OAuth2 handler
	oauth2Handlers := Handler(authzHandler,
		SetProvider(provider),
		SetAuthzForm(authzForm),
		SetAuthzEndpoint("/oauth2/authorize"),
		SetTokenEndpoint("/oauth2/tokens"),
		SetSTSMaxAge(time.Duration(8760)*time.Hour), // 1yr
		SetAuthzExpiration(time.Duration(1)*time.Minute),
		SetTokenExpiration(time.Duration(10)*time.Minute),
		SetLoginURL("https://api.hooklift.io/accounts/login", "redirect_to"),
	)

	log.Fatal(http.ListenAndServe(":3000", oauth2Handlers))
}
