// Package tokens handles requests for issuing and refreshing tokens
//
// 1.4.  Access Token
// Access tokens are credentials used to access protected resources.  An
// access token is a string representing an authorization issued to the
// client.  The string is usually opaque to the client.  Tokens
// represent specific scopes and durations of access, granted by the
// resource owner, and enforced by the resource server and authorization
// server.
//
// The token may denote an identifier used to retrieve the authorization
// information or may self-contain the authorization information in a
// verifiable manner (i.e., a token string consisting of some data and a
// signature).  Additional authentication credentials, which are beyond
// the scope of this specification, may be required in order for the
// client to use a token.
//
// The access token provides an abstraction layer, replacing different
// authorization constructs (e.g., username and password) with a single
// token understood by the resource server.  This abstraction enables
// issuing access tokens more restrictive than the authorization grant
// used to obtain them, as well as removing the resource server's need
// to understand a wide range of authentication methods.
//
// Access tokens can have different formats, structures, and methods of
// utilization (e.g., cryptographic properties) based on the resource
// server security requirements.  Access token attributes and the
// methods used to access protected resources are beyond the scope of
// this specification and are defined by companion specifications such
// as [RFC6750].
//
// -- http://tools.ietf.org/html/rfc6749#section-1.4
//
// 1.5.  Refresh Token
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

// 5.  Issuing an Access Token
//
// If the access token request is valid and authorized, the
// authorization server issues an access token and optional refresh
// token as described in Section 5.1.  If the request failed client
// authentication or is invalid, the authorization server returns an
// error response as described in Section 5.2.
//
// -- http://tools.ietf.org/html/rfc6749#section-5
//
// 5.1.  Successful Response
//
// The authorization server issues an access token and optional refresh
// token, and constructs the response by adding the following parameters
// to the entity-body of the HTTP response with a 200 (OK) status code:
//
//    access_token
//          REQUIRED.  The access token issued by the authorization server.
//
//    token_type
//          REQUIRED.  The type of the token issued as described in
//          Section 7.1.  Value is case insensitive.
//
//    expires_in
//          RECOMMENDED.  The lifetime in seconds of the access token.  For
//          example, the value "3600" denotes that the access token will
//          expire in one hour from the time the response was generated.
//          If omitted, the authorization server SHOULD provide the
//          expiration time via other means or document the default value.
//
//    refresh_token
//          OPTIONAL.  The refresh token, which can be used to obtain new
//          access tokens using the same authorization grant as described
//          in Section 6.
//
//    scope
//          OPTIONAL, if identical to the scope requested by the client;
//          otherwise, REQUIRED.  The scope of the access token as
//          described by Section 3.3.
//
// The parameters are included in the entity-body of the HTTP response
// using the "application/json" media type as defined by [RFC4627].  The
// parameters are serialized into a JavaScript Object Notation (JSON)
// structure by adding each parameter at the highest structure level.
// Parameter names and string values are included as JSON strings.
// Numerical values are included as JSON numbers.  The order of
// parameters does not matter and can vary.
//
// The authorization server MUST include the HTTP "Cache-Control"
// response header field [RFC2616] with a value of "no-store" in any
// response containing tokens, credentials, or other sensitive
// information, as well as the "Pragma" response header field [RFC2616]
// with a value of "no-cache".
//
// For example:
//
//      HTTP/1.1 200 OK
//      Content-Type: application/json;charset=UTF-8
//      Cache-Control: no-store
//      Pragma: no-cache
//
//      {
//        "access_token":"2YotnFZFEjr1zCsicMWpAA",
//        "token_type":"example",
//        "expires_in":3600,
//        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
//        "example_parameter":"example_value"
//      }
//
// The client MUST ignore unrecognized value names in the response.  The
// sizes of tokens and other values received from the authorization
// server are left undefined.  The client should avoid making
// assumptions about value sizes.  The authorization server SHOULD
// document the size of any value it issues.
//
// 5.2.  Error Response
//
// The authorization server responds with an HTTP 400 (Bad Request)
// status code (unless specified otherwise) and includes the following
// parameters with the response:
//
// error
//       REQUIRED.  A single ASCII [USASCII] error code from the
//       following:
//
//       invalid_request
//             The request is missing a required parameter, includes an
//             unsupported parameter value (other than grant type),
//             repeats a parameter, includes multiple credentials,
//             utilizes more than one mechanism for authenticating the
//             client, or is otherwise malformed.
//
//       invalid_client
//             Client authentication failed (e.g., unknown client, no
//             client authentication included, or unsupported
//             authentication method).  The authorization server MAY
//             return an HTTP 401 (Unauthorized) status code to indicate
//             which HTTP authentication schemes are supported.  If the
//             client attempted to authenticate via the "Authorization"
//             request header field, the authorization server MUST
//             respond with an HTTP 401 (Unauthorized) status code and
//             include the "WWW-Authenticate" response header field
//             matching the authentication scheme used by the clien
//       invalid_grant
//             The provided authorization grant (e.g., authorization
//             code, resource owner credentials) or refresh token is
//             invalid, expired, revoked, does not match the redirection
//             URI used in the authorization request, or was issued to
//             another client.
//
//       unauthorized_client
//             The authenticated client is not authorized to use this
//             authorization grant type.
//
//       unsupported_grant_type
//             The authorization grant type is not supported by the
//             authorization server.
//
//       invalid_scope
//             The requested scope is invalid, unknown, malformed, or
//             exceeds the scope granted by the resource owner.
//
//       Values for the "error" parameter MUST NOT include characters
//       outside the set %x20-21 / %x23-5B / %x5D-7E.
//
// error_description
//       OPTIONAL.  Human-readable ASCII [USASCII] text providing
//       additional information, used to assist the client developer in
//       understanding the error that occurred.
//       Values for the "error_description" parameter MUST NOT include
//       characters outside the set %x20-21 / %x23-5B / %x5D-7E.
//
// error_uri
//       OPTIONAL.  A URI identifying a human-readable web page with
//       information about the error, used to provide the client
//       developer with additional information about the error.
//       Values for the "error_uri" parameter MUST conform to the
//       URI-reference syntax and thus MUST NOT include characters
//       outside the set %x21 / %x23-5B / %x5D-7E.
//
// The parameters are included in the entity-body of the HTTP response
// using the "application/json" media type as defined by [RFC4627].  The
// parameters are serialized into a JSON structure by adding each
// parameter at the highest structure level.  Parameter names and string
// values are included as JSON strings.  Numerical values are included
// as JSON numbers.  The order of parameters does not matter and can
// vary.
//
//    For example:
//
//      HTTP/1.1 400 Bad Request
//      Content-Type: application/json;charset=UTF-8
//      Cache-Control: no-store
//      Pragma: no-cache
//
//      {
//        "error":"invalid_request"
//      }
func GenerateOrRefresh(w http.ResponseWriter, req *http.Request) {}

// 6.  Refreshing an Access Token
//
// If the authorization server issued a refresh token to the client, the
// client makes a refresh request to the token endpoint by adding the
// following parameters using the "application/x-www-form-urlencoded"
// format per Appendix B with a character encoding of UTF-8 in the HTTP
// request entity-body:
//
// grant_type
//       REQUIRED.  Value MUST be set to "refresh_token".
//
// refresh_token
//       REQUIRED.  The refresh token issued to the client.
//
// scope
//       OPTIONAL.  The scope of the access request as described by
//       Section 3.3.  The requested scope MUST NOT include any scope
//       not originally granted by the resource owner, and if omitted is
//       treated as equal to the scope originally granted by the
//       resource owner.
//
// Because refresh tokens are typically long-lasting credentials used to
// request additional access tokens, the refresh token is bound to the
// client to which it was issued.  If the client type is confidential or
// the client was issued client credentials (or assigned other
// authentication requirements), the client MUST authenticate with the
// authorization server as described in Section 3.2.1.
//
// For example, the client makes the following HTTP request using
// transport-layer security (with extra line breaks for display purposes
// only):
//
//   POST /token HTTP/1.1
//   Host: server.example.com
//   Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
//   Content-Type: application/x-www-form-urlencoded
//
//   grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
//
// The authorization server MUST:
//
// o  require client authentication for confidential clients or for any
//    client that was issued client credentials (or with other
//    authentication requirements),
//
// o  authenticate the client if client authentication is included and
//    ensure that the refresh token was issued to the authenticated
//    client, and
//
// o  validate the refresh token.
//
// If valid and authorized, the authorization server issues an access
// token as described in Section 5.1.  If the request failed
// verification or is invalid, the authorization server returns an error
// response as described in Section 5.2.
//
// The authorization server MAY issue a new refresh token, in which case
// the client MUST discard the old refresh token and replace it with the
// new refresh token.  The authorization server MAY revoke the old
// refresh token after issuing a new refresh token to the client.  If a
// new refresh token is issued, the refresh token scope MUST be
// identical to that of the refresh token included by the client in the
// request.
//
// -- http://tools.ietf.org/html/rfc6749#section-6
func refreshToken(w http.ResponseWriter, req *http.Request) {}
