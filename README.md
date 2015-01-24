# OAuth2 provider for Go

Implements an OAuth2 provider in a somewhat strict and opinionated manner. For instance:

* 3rd party client apps are required to always report the scopes they are trying to gain
access to when redirecting the resource owner to the authorization form.
* Always sends a Strict Transport Security header by default. You can disable it
by passing a STS max-age of 0.
* X-Frame-Options header is always sent along the authorization form
* X-XSS-Protection is always sent.
* Always requires 3rd-party client apps to send the `state` request parameter
in order to minimize risk of CSRF attacks.
* Requires passing a [request context](https://blog.golang.org/context) in order
for the authorization server to determine whether or not the resource owner is
authenticated and has valid session. Otherwise it redirects the resource owner to
the login page.

Implements:
* The OAuth 2.0 Authorization Framework: http://tools.ietf.org/html/rfc6749
* OAuth 2.0 Bearer Token Usage: http://tools.ietf.org/html/rfc6750
* OAuth 2.0 Token Revocation: https://tools.ietf.org/html/rfc7009

TODO:
* JSON Web Token (JWT): https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
* JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-12
*  OAuth 2.0 Dynamic Client Registration Protocol: https://tools.ietf.org/html/draft-ietf-oauth-dyn-reg-22
* SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-23

## Examples
