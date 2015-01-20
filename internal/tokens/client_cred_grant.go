package tokens

import "net/http"

// 4.4.  Client Credentials Grant
//
//    The client can request an access token using only its client
//    credentials (or other supported means of authentication) when the
//    client is requesting access to the protected resources under its
//    control, or those of another resource owner that have been previously
//    arranged with the authorization server (the method of which is beyond
//    the scope of this specification).
//
//    The client credentials grant type MUST only be used by confidential
//    clients.
//
//      +---------+                                  +---------------+
//      |         |                                  |               |
//      |         |>--(A)- Client Authentication --->| Authorization |
//      | Client  |                                  |     Server    |
//      |         |<--(B)---- Access Token ---------<|               |
//      |         |                                  |               |
//      +---------+                                  +---------------+
//
//                      Figure 6: Client Credentials Flow
//
//    The flow illustrated in Figure 6 includes the following steps:
//
//    (A)  The client authenticates with the authorization server and
//         requests an access token from the token endpoint.
//
//    (B)  The authorization server authenticates the client, and if valid,
//         issues an access token.
//
// 4.4.1.  Authorization Request and Response
//
//    Since the client authentication is used as the authorization grant,
//    no additional authorization request is needed.
//
// 4.4.2.  Access Token Request
//
//    The client makes a request to the token endpoint by adding the
//    following parameters using the "application/x-www-form-urlencoded"
//    format per Appendix B with a character encoding of UTF-8 in the HTTP
//    request entity-body:
//
//    grant_type
//          REQUIRED.  Value MUST be set to "client_credentials".
//
//    scope
//          OPTIONAL.  The scope of the access request as described by
//          Section 3.3.
//
//    The client MUST authenticate with the authorization server as
//    described in Section 3.2.1.
//
//    For example, the client makes the following HTTP request using
//    transport-layer security (with extra line breaks for display purposes
//    only):
//
//      POST /token HTTP/1.1
//      Host: server.example.com
//      Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
//      Content-Type: application/x-www-form-urlencoded
//
//      grant_type=client_credentials
//
//    The authorization server MUST authenticate the client.
//
// 4.4.3.  Access Token Response
//
//    If the access token request is valid and authorized, the
//    authorization server issues an access token as described in
//    Section 5.1.  A refresh token SHOULD NOT be included.  If the request
//    failed client authentication or is invalid, the authorization server
//    returns an error response as described in Section 5.2.
//
//    An example successful response:
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
//        "example_parameter":"example_value"
//      }
func clientCredentialsGrant(w http.ResponseWriter, req *http.Request) {}
