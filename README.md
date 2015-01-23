# OAuth2 provider for Go

Implements OAuth2 in a somewhat strict manner. For instance:

* Clients are required to always report the scopes they are trying to gain
access to when redirecting the resource owner to the authorization form.
* Always sends by default a Strict Transport Security header. However, you can disable it
by passing 0 as max-age.
* X-Frame-Options header is always sent along the authorization form
* X-XSS-Protection is always sent
* Always requires 3rd-party clients to send the `state` request parameter in order to minimize risk of CSRF attacks

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
