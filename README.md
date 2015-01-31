# OAuth2 provider library for Go

Implements an OAuth2 provider in a somewhat strict manner. For instance:

* 3rd party client apps are required to always report the scopes they are trying to gain
access to when redirecting the resource owner to the web authorization form.
* Always sends a `Strict-Transport-Security` header by default. You can disable it
by passing a STS max-age of 0.
* `X-Frame-Options` header is always sent along the authorization form
* `X-XSS-Protection` is always sent.
* Always requires 3rd-party client apps to send the `state` request parameter
in order to minimize risk of CSRF attacks.
* Always requires clients to register redirect URIs with a HTTPS scheme.
* Does not allow clients to use dynamic redirect URIs.
* Does refresh-token rotation upon access-token refresh.

## How to use
This library was designed as a regular Go's HTTP handler. A brief example:

```go
package main

import (
	"log"
	"net/http"

	"github.com/hooklift/oauth2"
	"github.com/hooklift/oauth2/providers/test"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hellow World!"))
	})

	provider := test.NewProvider(true)
	authzHandler := oauth2.AuthzHandler(mux, provider)
	oauth2Handlers := oauth2.Handler(authzHandler, provider)

	log.Fatal(http.ListenAndServe(":3000", oauth2Handlers))
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

