// Package authorizations handles requests for granting and revoking authorization grants
//
// An authorization grant is a credential representing the resource
// owner's authorization (to access its protected resources) used by the
// client to obtain an access token.  The rfc6749 spec defines four
// grant types -- authorization code, implicit, resource owner password
// credentials, and client credentials -- as well as an extensibility
// mechanism for defining additional types.
//
// -- http://tools.ietf.org/html/rfc6749#section-1.3
//
// 4.  Obtaining Authorization
//
// To request an access token, the client obtains authorization from the
// resource owner.  The authorization is expressed in the form of an
// authorization grant, which the client uses to request the access
// token.  OAuth defines four grant types: authorization code, implicit,
// resource owner password credentials, and client credentials.  It also
// provides an extension mechanism for defining additional grant types.
//
// 4.1. Authorization Code Grant
//
// The authorization code grant type is used to obtain both access
// tokens and refresh tokens and is optimized for confidential clients.
// Since this is a redirection-based flow, the client must be capable of
// interacting with the resource owner's user-agent (typically a web
// browser) and capable of receiving incoming requests (via redirection)
// from the authorization server.
//
//   +----------+
//   | Resource |
//   |   Owner  |
//   |          |
//   +----------+
//        ^
//        |
//       (B)
//   +----|-----+          Client Identifier      +---------------+
//   |         -+----(A)-- & Redirection URI ---->|               |
//   |  User-   |                                 | Authorization |
//   |  Agent  -+----(B)-- User authenticates --->|     Server    |
//   |          |                                 |               |
//   |         -+----(C)-- Authorization Code ---<|               |
//   +-|----|---+                                 +---------------+
//     |    |                                         ^      v
//    (A)  (C)                                        |      |
//     |    |                                         |      |
//     ^    v                                         |      |
//   +---------+                                      |      |
//   |         |>---(D)-- Authorization Code ---------'      |
//   |  Client |          & Redirection URI                  |
//   |         |                                             |
//   |         |<---(E)----- Access Token -------------------'
//   +---------+       (w/ Optional Refresh Token)
//
// Note: The lines illustrating steps (A), (B), and (C) are broken into
// two parts as they pass through the user-agent.
//
//                   Figure 3: Authorization Code Flow
//
// The flow illustrated in Figure 3 includes the following steps:
//
// (A)  The client initiates the flow by directing the resource owner's
//      user-agent to the authorization endpoint.  The client includes
//      its client identifier, requested scope, local state, and a
//      redirection URI to which the authorization server will send the
//      user-agent back once access is granted (or denied).
//
// (B)  The authorization server authenticates the resource owner (via
//      the user-agent) and establishes whether the resource owner
//      grants or denies the client's access request.
//
// (C)  Assuming the resource owner grants access, the authorization
//      server redirects the user-agent back to the client using the
//      redirection URI provided earlier (in the request or during
//      client registration).  The redirection URI includes an
//      authorization code and any local state provided by the client
//      earlier.
//
// (D)  The client requests an access token from the authorization
//      server's token endpoint by including the authorization code
//      received in the previous step.  When making the request, the
//      client authenticates with the authorization server.  The client
//      includes the redirection URI used to obtain the authorization
//      code for verification.
//
// (E)  The authorization server authenticates the client, validates the
//      authorization code, and ensures that the redirection URI
//      received matches the URI used to redirect the client in
//      step (C).  If valid, the authorization server responds back with
//      an access token and, optionally, a refresh token.
//
// -- http://tools.ietf.org/html/rfc6749#section-4.1
package authorizations

import "net/http"

// Handlers is a map to functions where each function handles a particular HTTP
// verb or method.
var Handlers map[string]func(http.ResponseWriter, *http.Request) = map[string]func(http.ResponseWriter, *http.Request){
	"POST":   CreateGrant,
	"DELETE": RevokeGrant,
}

// Grant authorizations to get access tokens.
//
// 4.1.1.  Authorization Request
// The client constructs the request URI by adding the following
// parameters to the query component of the authorization endpoint URI
// using the "application/x-www-form-urlencoded" format, per Appendix B:
//
// response_type
//       REQUIRED.  Value MUST be set to "code".
//
// client_id
//       REQUIRED.  The client identifier as described in Section 2.2.
//
// redirect_uri
//       OPTIONAL.  As described in Section 3.1.2.
//
// scope
//       OPTIONAL.  The scope of the access request as described by Section 3.3.
//
// state
//       RECOMMENDED.  An opaque value used by the client to maintain
//       state between the request and callback.  The authorization
//       server includes this value when redirecting the user-agent back
//       to the client.  The parameter SHOULD be used for preventing
//       cross-site request forgery as described in Section 10.12.
//
// The client directs the resource owner to the constructed URI using an
// HTTP redirection response, or by other means available to it via the
// user-agent.
//
// For example, the client directs the user-agent to make the following
// HTTP request using TLS (with extra line breaks for display purposes
// only):
//
//  GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
//      &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
//  Host: server.example.com
//
// The authorization server validates the request to ensure that all
// required parameters are present and valid.  If the request is valid,
// the authorization server authenticates the resource owner and obtains
// an authorization decision (by asking the resource owner or by
// establishing approval via other means).
//
// When a decision is established, the authorization server directs the
// user-agent to the provided client redirection URI using an HTTP
// redirection response, or by other means available to it via the
// user-agent.
//
// -- http://tools.ietf.org/html/rfc6749#section-4.1.1
//
// 4.1.2.  Authorization Response
//
// If the resource owner grants the access request, the authorization
// server issues an authorization code and delivers it to the client by
// adding the following parameters to the query component of the
// redirection URI using the "application/x-www-form-urlencoded" format,
// per Appendix B:
//
// code
//       REQUIRED.  The authorization code generated by the
//       authorization server.  The authorization code MUST expire
//       shortly after it is issued to mitigate the risk of leaks.  A
//       maximum authorization code lifetime of 10 minutes is
//       RECOMMENDED.  The client MUST NOT use the authorization code
//       more than once.  If an authorization code is used more than
//       once, the authorization server MUST deny the request and SHOULD
//       revoke (when possible) all tokens previously issued based on
//       that authorization code.  The authorization code is bound to
//       the client identifier and redirection URI.
//
// state
//       REQUIRED if the "state" parameter was present in the client
//       authorization request.  The exact value received from the
//       client.
//
// For example, the authorization server redirects the user-agent by
// sending the following HTTP response:
//
// HTTP/1.1 302 Found
// Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
//    The client MUST ignore unrecognized response parameters.  The
//    authorization code string size is left undefined by this
//    specification.  The client should avoid making assumptions about code
//    value sizes.  The authorization server SHOULD document the size of
//    any value it issues.
//
// -- http://tools.ietf.org/html/rfc6749#section-4.1.2
//
// 4.1.2.1.  Error Response
//
// If the request fails due to a missing, invalid, or mismatching
// redirection URI, or if the client identifier is missing or invalid,
// the authorization server SHOULD inform the resource owner of the
// error and MUST NOT automatically redirect the user-agent to the
// invalid redirection URI.
//
// If the resource owner denies the access request or if the request
// fails for reasons other than a missing or invalid redirection URI,
// the authorization server informs the client by adding the following
// parameters to the query component of the redirection URI using the
// "application/x-www-form-urlencoded" format, per Appendix B:
//
// error
//       REQUIRED.  A single ASCII [USASCII] error code from the
//       following:
//
//       invalid_request
//             The request is missing a required parameter, includes an
//             invalid parameter value, includes a parameter more than
//             once, or is otherwise malformed.
//       unauthorized_client
//             The client is not authorized to request an authorization
//             code using this method.
//
//       access_denied
//             The resource owner or authorization server denied the
//             request.
//
//       unsupported_response_type
//             The authorization server does not support obtaining an
//             authorization code using this method.
//
//       invalid_scope
//             The requested scope is invalid, unknown, or malformed.
//
//       server_error
//             The authorization server encountered an unexpected
//             condition that prevented it from fulfilling the request.
//             (This error code is needed because a 500 Internal Server
//             Error HTTP status code cannot be returned to the client
//             via an HTTP redirect.)
//
//       temporarily_unavailable
//             The authorization server is currently unable to handle
//             the request due to a temporary overloading or maintenance
//             of the server.  (This error code is needed because a 503
//             Service Unavailable HTTP status code cannot be returned
//             to the client via an HTTP redirect.)
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
// state
//       REQUIRED if a "state" parameter was present in the client
//       authorization request.  The exact value received from the
//       client.
//
// For example, the authorization server redirects the user-agent by
// sending the following HTTP response:
//
// HTTP/1.1 302 Found
// Location: https://client.example.com/cb?error=access_denied&state=xyz
//
// -- http://tools.ietf.org/html/rfc6749#section-4.1.2.1
//
func CreateGrant(w http.ResponseWriter, req *http.Request) {}

func authCodeGrant(w http.ResponseWriter, req *http.Request)                 {}
func implicitGrant(w http.ResponseWriter, req *http.Request)                 {}
func resourceOwnerCredentialsGrant(w http.ResponseWriter, req *http.Request) {}
func clientCredentialsGrant(w http.ResponseWriter, req *http.Request)        {}

// Revoke blocks all associated tokens from making further requests.
func RevokeGrant(w http.ResponseWriter, req *http.Request) {}
