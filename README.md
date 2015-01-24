# OAuth2 provider library for Go

Implements an OAuth2 provider in a somewhat strict and opinionated manner. For instance:

* 3rd party client apps are required to always report the scopes they are trying to gain
access to when redirecting the resource owner to the authorization form.
* Always sends a `Strict-Transport-Security` header by default. You can disable it
by passing a STS max-age of 0.
* `X-Frame-Options` header is always sent along the authorization form
* `X-XSS-Protection` is always sent.
* Always requires 3rd-party client apps to send the `state` request parameter
in order to minimize risk of CSRF attacks.

## How to use
1. This library was designed as a regular HTTP handler. An example about how to use
in general terms is below:

```go
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
```

Lastly, don't forget to implement the [Provider](https://github.com/hooklift/oauth2/blob/master/provider.go#L45-L85) interface :)


## Implemented specs
* The OAuth 2.0 Authorization Framework: http://tools.ietf.org/html/rfc6749
* OAuth 2.0 Bearer Token Usage: http://tools.ietf.org/html/rfc6750
* OAuth 2.0 Token Revocation: https://tools.ietf.org/html/rfc7009

TODO:
* JSON Web Token (JWT): https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
* JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
*  OAuth 2.0 Dynamic Client Registration Protocol: https://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-22
* SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-23

