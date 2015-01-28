package oauth2

import (
	"log"
	"net/http"
	"time"
)

func ExampleExamples() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hellow World!"))
	})

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
			<form>
			 <input type="hidden" name="client_id" value="{{.Client.ID}}"/>
			 <input type="hidden" name="response_type" value="{{.GrantType}}"/>
			 <input type="hidden" name="redirect_uri" value="{{.Client.RedirectURL}}"/>
			 <input type="hidden" name="scope" value="{{StringifyScopes .Scopes}}"/>
			 <input type="hidden" name="state" value="{{.State}}"/>
			</form>
		{{end}}
		</body>
		</html>
	`
	reqHandler := Handler(
		mux,
		SetTokenEndpoint("/oauth2/tokens"),
		SetAuthzEndpoint("/oauth2/authzs"),
		SetRevokeEndpoint("/oauth2/revoke"),
		// When setting token expiration times, the lower they are the more
		// frequent your server is going to receive refresh tokens requests.
		// When the opposite is done, you will be widening the time window for
		// successful attacks. A reasonable value is 5 or 10 minutes.
		SetTokenExpiration(time.Duration(5)*time.Minute),
		SetAuthzExpiration(time.Duration(1)*time.Minute),
		// Disables Strict Transport Security for development purposes
		SetSTSMaxAge(0),
		// Sets authorization HTML form
		SetAuthzForm(authzForm),
		//SetSecret("B4oitDPj=JYECrAZr*igmnbcJTguVvkYJXMVpdMoqe9doHXb4#"),
		SetProvider(nil),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
