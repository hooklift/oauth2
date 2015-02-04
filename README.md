# OAuth2 provider library for Go
[![GoDoc](https://godoc.org/github.com/hooklift/oauth2?status.svg)](https://godoc.org/github.com/hooklift/oauth2)
[![Build Status](https://travis-ci.org/hooklift/oauth2.svg?branch=master)](https://travis-ci.org/hooklift/oauth2)

Implements OAuth2 HTTP dancing in a somewhat strict manner. For instance:

* 3rd party client apps are required to always report the scopes they are trying to gain
access to when redirecting the resource owner to the web authorization form.
* Always sends a `Strict-Transport-Security` header by default. You can disable it
by passing a STS max-age of 0.
* `X-Frame-Options` header is always sent along the authorization form
* `X-XSS-Protection` is always sent.
* Requires 3rd-party client apps to send the `state` request parameter
in order to minimize risk of CSRF attacks.
* Checks redirect URIs against pre-registered client URIs
* Requires redirect URIs to use HTTPS scheme.
* Does not allow clients to use dynamic redirect URIs.
* Forces refresh-token rotation upon access-token refresh.

### OAuth2 flows supported
* Authorization Code
* Implicit
* Resource Owner Password Credentials
* Client Credentials

### Non goals
It is not a goal of this library to support:

* Authentication
* Session management
* Backend storage, instead we defined an [interface](https://github.com/hooklift/oauth2/blob/master/oauth2.go#L23-L111) for users to implement and plug any backend storage of their preference.

## How to use
This library was designed as a regular Go's HTTP handler. A brief example about how to use it:

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/hooklift/oauth2"
	"github.com/hooklift/oauth2/providers/test"
)

func main() {
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
			 <input type="hidden" name="scope" value="{{StringifyScopes .Scopes}}"/>
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

	// A provider that implements oauth2.Provider interface
	provider := test.NewProvider(true)

	// Authorization handler to protect resources in this server
	authzHandler := oauth2.AuthzHandler(mux, provider)

	// OAuth2 handler to handle authorization and token requests
	oauth2Handlers := oauth2.Handler(authzHandler,
		oauth2.SetProvider(provider),
		oauth2.SetAuthzForm(authzForm),
		oauth2.SetAuthzEndpoint("/oauth2/authorize"),
		oauth2.SetTokenEndpoint("/oauth2/tokens"),
		// Strict Transport Security max age configuration
		oauth2.SetSTSMaxAge(time.Duration(8760)*time.Hour), // 1yr
		oauth2.SetAuthzExpiration(time.Duration(1)*time.Minute),
		oauth2.SetTokenExpiration(time.Duration(10)*time.Minute),
		oauth2.SetLoginURL("https://api.hooklift.io/accounts/login", "redirect_to"),
	)

	log.Fatal(http.ListenAndServe(":3000", oauth2Handlers))
}
```

Lastly, don't forget to implement the [Provider](https://github.com/hooklift/oauth2/blob/master/oauth2.go#L23-L111) interface.

## Implemented specs
* The OAuth 2.0 Authorization Framework: http://tools.ietf.org/html/rfc6749
* OAuth 2.0 Bearer Token Usage: http://tools.ietf.org/html/rfc6750
* OAuth 2.0 Token Revocation: https://tools.ietf.org/html/rfc7009

Also implements some considerations from: https://tools.ietf.org/html/rfc6819

