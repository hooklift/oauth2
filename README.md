# OAuth2 provider library for Go

Implements an OAuth2 provider in a somewhat strict manner. For instance:

* 3rd party client apps are required to always report the scopes they are trying to gain
access to when redirecting the resource owner to the authorization form.
* Always sends a `Strict-Transport-Security` header by default. You can disable it
by passing a STS max-age of 0.
* `X-Frame-Options` header is always sent along the authorization form
* `X-XSS-Protection` is always sent.
* Always requires 3rd-party client apps to send the `state` request parameter
in order to minimize risk of CSRF attacks.
* Always requires clients to use callback URLs with a HTTPS scheme.

## How to use
This library was designed as a regular Go's HTTP handler. An example about how to use,
in general terms, is below:

```go
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
		SetProvider(nil),
	)

	log.Fatal(http.ListenAndServe(":3000", reqHandler))
}
```

Lastly, don't forget to implement the [Provider](https://github.com/hooklift/oauth2/blob/master/provider.go#L45-L85) interface :)


## Implemented specs
* The OAuth 2.0 Authorization Framework: http://tools.ietf.org/html/rfc6749
* OAuth 2.0 Bearer Token Usage: http://tools.ietf.org/html/rfc6750
* OAuth 2.0 Token Revocation: https://tools.ietf.org/html/rfc7009

Also implements some applicable considerations from: https://tools.ietf.org/html/rfc6819

TODO:
* JSON Web Token (JWT): https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
* JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
*  OAuth 2.0 Dynamic Client Registration Protocol: https://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-22
* SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-23

