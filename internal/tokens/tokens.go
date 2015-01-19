// Package tokens handles requests for generating and refreshing tokens
//
// Access tokens are credentials used to access protected resources.  An
// access token is a string representing an authorization issued to the
// client.  The string is usually opaque to the client.  Tokens
// represent specific scopes and durations of access, granted by the
// resource owner, and enforced by the resource server and authorization
// server.

// The token may denote an identifier used to retrieve the authorization
// information or may self-contain the authorization information in a
// verifiable manner (i.e., a token string consisting of some data and a
// signature).  Additional authentication credentials, which are beyond
// the scope of this specification, may be required in order for the
// client to use a token.

// The access token provides an abstraction layer, replacing different
// authorization constructs (e.g., username and password) with a single
// token understood by the resource server.  This abstraction enables
// issuing access tokens more restrictive than the authorization grant
// used to obtain them, as well as removing the resource server's need
// to understand a wide range of authentication methods.

// Access tokens can have different formats, structures, and methods of
// utilization (e.g., cryptographic properties) based on the resource
// server security requirements.  Access token attributes and the
// methods used to access protected resources are beyond the scope of
// this specification and are defined by companion specifications such
// as [RFC6750].
//
// -- http://tools.ietf.org/html/rfc6749#section-1.4
//
// Refresh tokens are credentials used to obtain access tokens.  Refresh
// tokens are issued to the client by the authorization server and are
// used to obtain a new access token when the current access token
// becomes invalid or expires, or to obtain additional access tokens
// with identical or narrower scope (access tokens may have a shorter
// lifetime and fewer permissions than authorized by the resource
// owner).  Issuing a refresh token is optional at the discretion of the
// authorization server.  If the authorization server issues a refresh
// token, it is included when issuing an access token (i.e., step (D) in
// Figure 1).
//
// A refresh token is a string representing the authorization granted to
// the client by the resource owner.  The string is usually opaque to
// the client.  The token denotes an identifier used to retrieve the
// authorization information.  Unlike access tokens, refresh tokens are
// intended for use only with authorization servers and are never sent
// to resource servers.
//
//  +--------+                                           +---------------+
//  |        |--(A)------- Authorization Grant --------->|               |
//  |        |                                           |               |
//  |        |<-(B)----------- Access Token -------------|               |
//  |        |               & Refresh Token             |               |
//  |        |                                           |               |
//  |        |                            +----------+   |               |
//  |        |--(C)---- Access Token ---->|          |   |               |
//  |        |                            |          |   |               |
//  |        |<-(D)- Protected Resource --| Resource |   | Authorization |
//  | Client |                            |  Server  |   |     Server    |
//  |        |--(E)---- Access Token ---->|          |   |               |
//  |        |                            |          |   |               |
//  |        |<-(F)- Invalid Token Error -|          |   |               |
//  |        |                            +----------+   |               |
//  |        |                                           |               |
//  |        |--(G)----------- Refresh Token ----------->|               |
//  |        |                                           |               |
//  |        |<-(H)----------- Access Token -------------|               |
//  +--------+           & Optional Refresh Token        +---------------+
//
//               Figure 2: Refreshing an Expired Access Token
//
// The flow illustrated in Figure 2 includes the following steps:
//
// (A)  The client requests an access token by authenticating with the
//      authorization server and presenting an authorization grant.
//
// (B)  The authorization server authenticates the client and validates
//      the authorization grant, and if valid, issues an access token
//      and a refresh token.
//
// (C)  The client makes a protected resource request to the resource
//      server by presenting the access token.
//
// (D)  The resource server validates the access token, and if valid,
//      serves the request.
//
// (E)  Steps (C) and (D) repeat until the access token expires.  If the
//      client knows the access token expired, it skips to step (G);
//      otherwise, it makes another protected resource request.
//
// (F)  Since the access token is invalid, the resource server returns
//      an invalid token error.
//
// (G)  The client requests a new access token by authenticating with
//      the authorization server and presenting the refresh token.  The
//      client authentication requirements are based on the client type
//      and on the authorization server policies.
//
// (H)  The authorization server authenticates the client and validates
//      the refresh token, and if valid, issues a new access token (and,
//      optionally, a new refresh token).
//
// Steps (C), (D), (E), and (F) are outside the scope of this
// specification, as described in Section 7.
//
// -- http://tools.ietf.org/html/rfc6749#section-1.5
package tokens

import "net/http"

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var Handlers map[string]func(http.ResponseWriter, *http.Request) = map[string]func(http.ResponseWriter, *http.Request){
	"POST": GenerateOrRefresh,
}

// GenerateToken generates an access token.
//
// 4.1.3.  Access Token Request
//
// The client makes a request to the token endpoint by sending the
// following parameters using the "application/x-www-form-urlencoded"
// format per Appendix B with a character encoding of UTF-8 in the HTTP
// request entity-body:
//
// grant_type
//       REQUIRED.  Value MUST be set to "authorization_code".
//
// code
//       REQUIRED.  The authorization code received from the
//       authorization server.
//
// redirect_uri
//       REQUIRED, if the "redirect_uri" parameter was included in the
//       authorization request as described in Section 4.1.1, and their
//       values MUST be identical.
//
// client_id
//       REQUIRED, if the client is not authenticating with the
//       authorization server as described in Section 3.2.1.
//
// If the client type is confidential or the client was issued client
// credentials (or assigned other authentication requirements), the
// client MUST authenticate with the authorization server as described
// in Section 3.2.1.
//
// For example, the client makes the following HTTP request using TLS
// (with extra line breaks for display purposes only):
//
//   POST /token HTTP/1.1
//   Host: server.example.com
//   Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
//   Content-Type: application/x-www-form-urlencoded
//
//   grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
//   &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
//
// The authorization server MUST:
//
// o  require client authentication for confidential clients or for any
//    client that was issued client credentials (or with other
//    authentication requirements),
//
// o  authenticate the client if client authentication is included,
//
// o  ensure that the authorization code was issued to the authenticated
//    confidential client, or if the client is public, ensure that the
//    code was issued to "client_id" in the request,
//
// o  verify that the authorization code is valid, and
//
// o  ensure that the "redirect_uri" parameter is present if the
//    "redirect_uri" parameter was included in the initial authorization
//    request as described in Section 4.1.1, and if included ensure that
//    their values are identical.
//
// -- http://tools.ietf.org/html/rfc6749#section-4.1.3
//
// 4.1.4.  Access Token Response
//
// If the access token request is valid and authorized, the
// authorization server issues an access token and optional refresh
// token as described in Section 5.1.  If the request client
// authentication failed or is invalid, the authorization server returns
// an error response as described in Section 5.2.
//
// An example successful response:
//
// HTTP/1.1 200 OK
// Content-Type: application/json;charset=UTF-8
// Cache-Control: no-store
// Pragma: no-cache
//
// {
//   "access_token":"2YotnFZFEjr1zCsicMWpAA",
//   "token_type":"example",
//   "expires_in":3600,
//   "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
//   "example_parameter":"example_value"
// }
// -- http://tools.ietf.org/html/rfc6749#section-4.1.4
func GenerateOrRefresh(w http.ResponseWriter, req *http.Request) {}

func authCodeGrant(w http.ResponseWriter, req *http.Request)                 {}
func implicitGrant(w http.ResponseWriter, req *http.Request)                 {}
func resourceOwnerCredentialsGrant(w http.ResponseWriter, req *http.Request) {}
func clientCredentialsGrant(w http.ResponseWriter, req *http.Request)        {}

func refreshToken(w http.ResponseWriter, req *http.Request) {}
