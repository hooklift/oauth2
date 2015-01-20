package tokens

import "net/http"

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
func authCodeGrant(w http.ResponseWriter, req *http.Request) {}
