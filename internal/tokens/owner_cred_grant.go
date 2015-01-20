package tokens

import "net/http"

// 4.3.  Resource Owner Password Credentials Grant
//
//    The resource owner password credentials grant type is suitable in
//    cases where the resource owner has a trust relationship with the
//    client, such as the device operating system or a highly privileged
//    application.  The authorization server should take special care when
//    enabling this grant type and only allow it when other flows are not
//    viable.
//
//    This grant type is suitable for clients capable of obtaining the
//    resource owner's credentials (username and password, typically using
//    an interactive form).  It is also used to migrate existing clients
//    using direct authentication schemes such as HTTP Basic or Digest
//    authentication to OAuth by converting the stored credentials to an
//    access token.
//
//      +----------+
//      | Resource |
//      |  Owner   |
//      |          |
//      +----------+
//           v
//           |    Resource Owner
//          (A) Password Credentials
//           |
//           v
//      +---------+                                  +---------------+
//      |         |>--(B)---- Resource Owner ------->|               |
//      |         |         Password Credentials     | Authorization |
//      | Client  |                                  |     Server    |
//      |         |<--(C)---- Access Token ---------<|               |
//      |         |    (w/ Optional Refresh Token)   |               |
//      +---------+                                  +---------------+
//
//             Figure 5: Resource Owner Password Credentials Flow
//
//    The flow illustrated in Figure 5 includes the following steps:
//
//    (A)  The resource owner provides the client with its username and
//         password.
//
//    (B)  The client requests an access token from the authorization
//         server's token endpoint by including the credentials received
//         from the resource owner.  When making the request, the client
//         authenticates with the authorization server.
//
//    (C)  The authorization server authenticates the client and validates
//         the resource owner credentials, and if valid, issues an access
//         token.
//
// 4.3.1.  Authorization Request and Response
//
//    The method through which the client obtains the resource owner
//    credentials is beyond the scope of this specification.  The client
//    MUST discard the credentials once an access token has been obtained.
//
// 4.3.2.  Access Token Request
//
//    The client makes a request to the token endpoint by adding the
//    following parameters using the "application/x-www-form-urlencoded"
//    format per Appendix B with a character encoding of UTF-8 in the HTTP
//    request entity-body:
//
//    grant_type
//          REQUIRED.  Value MUST be set to "password".
//
//    username
//          REQUIRED.  The resource owner username.
//
//    password
//          REQUIRED.  The resource owner password.
//
//    scope
//          OPTIONAL.  The scope of the access request as described by
//          Section 3.3.
//
//    If the client type is confidential or the client was issued client
//    credentials (or assigned other authentication requirements), the
//    client MUST authenticate with the authorization server as described
//    in Section 3.2.1.
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
//      grant_type=password&username=johndoe&password=A3ddj3w
//
//    The authorization server MUST:
//
//    o  require client authentication for confidential clients or for any
//       client that was issued client credentials (or with other
//       authentication requirements),
//
//    o  authenticate the client if client authentication is included, and
//
//    o  validate the resource owner password credentials using its
//       existing password validation algorithm.
//
//    Since this access token request utilizes the resource owner's
//    password, the authorization server MUST protect the endpoint against
//    brute force attacks (e.g., using rate-limitation or generating
//    alerts).
//
// 4.3.3.  Access Token Response
//
//    If the access token request is valid and authorized, the
//    authorization server issues an access token and optional refresh
//    token as described in Section 5.1.  If the request failed client
//    authentication or is invalid, the authorization server returns an
//    error response as described in Section 5.2.
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
//        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
//        "example_parameter":"example_value"
//      }
func resourceOwnerCredentialsGrant(w http.ResponseWriter, req *http.Request) {}
