package authorizations

import "net/http"

// 4.2.  Implicit Grant
//
//    The implicit grant type is used to obtain access tokens (it does not
//    support the issuance of refresh tokens) and is optimized for public
//    clients known to operate a particular redirection URI.  These clients
//    are typically implemented in a browser using a scripting language
//    such as JavaScript.
//
//    Since this is a redirection-based flow, the client must be capable of
//    interacting with the resource owner's user-agent (typically a web
//    browser) and capable of receiving incoming requests (via redirection)
//    from the authorization server.
//
//    Unlike the authorization code grant type, in which the client makes
//    separate requests for authorization and for an access token, the
//    client receives the access token as the result of the authorization
//    request.
//
//    The implicit grant type does not include client authentication, and
//    relies on the presence of the resource owner and the registration of
//    the redirection URI.  Because the access token is encoded into the
//    redirection URI, it may be exposed to the resource owner and other
//    applications residing on the same device.
//
//
//      +----------+
//      | Resource |
//      |  Owner   |
//      |          |
//      +----------+
//           ^
//           |
//          (B)
//      +----|-----+          Client Identifier     +---------------+
//      |         -+----(A)-- & Redirection URI --->|               |
//      |  User-   |                                | Authorization |
//      |  Agent  -|----(B)-- User authenticates -->|     Server    |
//      |          |                                |               |
//      |          |<---(C)--- Redirection URI ----<|               |
//      |          |          with Access Token     +---------------+
//      |          |            in Fragment
//      |          |                                +---------------+
//      |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
//      |          |          without Fragment      |     Client    |
//      |          |                                |    Resource   |
//      |     (F)  |<---(E)------- Script ---------<|               |
//      |          |                                +---------------+
//      +-|--------+
//        |    |
//       (A)  (G) Access Token
//        |    |
//        ^    v
//      +---------+
//      |         |
//      |  Client |
//      |         |
//      +---------+
//
//    Note: The lines illustrating steps (A) and (B) are broken into two
//    parts as they pass through the user-agent.
//
//                        Figure 4: Implicit Grant Flow
//
//    The flow illustrated in Figure 4 includes the following steps:
//
//    (A)  The client initiates the flow by directing the resource owner's
//         user-agent to the authorization endpoint.  The client includes
//         its client identifier, requested scope, local state, and a
//         redirection URI to which the authorization server will send the
//         user-agent back once access is granted (or denied).
//
//    (B)  The authorization server authenticates the resource owner (via
//         the user-agent) and establishes whether the resource owner
//         grants or denies the client's access request.
//
//    (C)  Assuming the resource owner grants access, the authorization
//         server redirects the user-agent back to the client using the
//         redirection URI provided earlier.  The redirection URI includes
//         the access token in the URI fragment.
//
//    (D)  The user-agent follows the redirection instructions by making a
//         request to the web-hosted client resource (which does not
//         include the fragment per [RFC2616]).  The user-agent retains the
//         fragment information locally.
//
//    (E)  The web-hosted client resource returns a web page (typically an
//         HTML document with an embedded script) capable of accessing the
//         full redirection URI including the fragment retained by the
//         user-agent, and extracting the access token (and other
//         parameters) contained in the fragment.
//
//    (F)  The user-agent executes the script provided by the web-hosted
//         client resource locally, which extracts the access token.
//
//    (G)  The user-agent passes the access token to the client.
//
//    See Sections 1.3.2 and 9 for background on using the implicit grant.
//    See Sections 10.3 and 10.16 for important security considerations
//    when using the implicit grant.
//
// 4.2.1.  Authorization Request
//
//    The client constructs the request URI by adding the following
//    parameters to the query component of the authorization endpoint URI
//    using the "application/x-www-form-urlencoded" format, per Appendix B:
//
//    response_type
//          REQUIRED.  Value MUST be set to "token".
//
//    client_id
//          REQUIRED.  The client identifier as described in Section 2.2.
//
//    redirect_uri
//          OPTIONAL.  As described in Section 3.1.2.
//
//    scope
//          OPTIONAL.  The scope of the access request as described by
//          Section 3.3.
//
//    state
//          RECOMMENDED.  An opaque value used by the client to maintain
//          state between the request and callback.  The authorization
//          server includes this value when redirecting the user-agent back
//          to the client.  The parameter SHOULD be used for preventing
//          cross-site request forgery as described in Section 10.12.
//
//    The client directs the resource owner to the constructed URI using an
//    HTTP redirection response, or by other means available to it via the
//    user-agent.
//
//    For example, the client directs the user-agent to make the following
//    HTTP request using TLS (with extra line breaks for display purposes
//    only):
//
//     GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
//         &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
//     Host: server.example.com
//
//    The authorization server validates the request to ensure that all
//    required parameters are present and valid.  The authorization server
//    MUST verify that the redirection URI to which it will redirect the
//    access token matches a redirection URI registered by the client as
//    described in Section 3.1.2.
//
//    If the request is valid, the authorization server authenticates the
//    resource owner and obtains an authorization decision (by asking the
//    resource owner or by establishing approval via other means).
//
//    When a decision is established, the authorization server directs the
//    user-agent to the provided client redirection URI using an HTTP
//    redirection response, or by other means available to it via the
//    user-agent.
//
// 4.2.2.  Access Token Response
//
//    If the resource owner grants the access request, the authorization
//    server issues an access token and delivers it to the client by adding
//    the following parameters to the fragment component of the redirection
//    URI using the "application/x-www-form-urlencoded" format, per
//    Appendix B:
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
//    scope
//          OPTIONAL, if identical to the scope requested by the client;
//          otherwise, REQUIRED.  The scope of the access token as
//          described by Section 3.3.
//
//    state
//          REQUIRED if the "state" parameter was present in the client
//          authorization request.  The exact value received from the
//          client.
//
//    The authorization server MUST NOT issue a refresh token.
//
//    For example, the authorization server redirects the user-agent by
//    sending the following HTTP response (with extra line breaks for
//    display purposes only):
//
//      HTTP/1.1 302 Found
//      Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
//                &state=xyz&token_type=example&expires_in=3600
//
//    Developers should note that some user-agents do not support the
//    inclusion of a fragment component in the HTTP "Location" response
//    header field.  Such clients will require using other methods for
//    redirecting the client than a 3xx redirection response -- for
//    example, returning an HTML page that includes a 'continue' button
//    with an action linked to the redirection URI.
//
//    The client MUST ignore unrecognized response parameters.  The access
//    token string size is left undefined by this specification.  The
//    client should avoid making assumptions about value sizes.  The
//    authorization server SHOULD document the size of any value it issues.
//
// 4.2.2.1.  Error Response
//
//    If the request fails due to a missing, invalid, or mismatching
//    redirection URI, or if the client identifier is missing or invalid,
//    the authorization server SHOULD inform the resource owner of the
//    error and MUST NOT automatically redirect the user-agent to the
//    invalid redirection URI.
//
//    If the resource owner denies the access request or if the request
//    fails for reasons other than a missing or invalid redirection URI,
//    the authorization server informs the client by adding the following
//    parameters to the fragment component of the redirection URI using the
//    "application/x-www-form-urlencoded" format, per Appendix B:
//
//    error
//          REQUIRED.  A single ASCII [USASCII] error code from the
//          following:
//
//          invalid_request
//                The request is missing a required parameter, includes an
//                invalid parameter value, includes a parameter more than
//                once, or is otherwise malformed.
//
//          unauthorized_client
//                The client is not authorized to request an access token
//                using this method.
//
//          access_denied
//                The resource owner or authorization server denied the
//                request.
//
//          unsupported_response_type
//                The authorization server does not support obtaining an
//                access token using this method.
//
//          invalid_scope
//                The requested scope is invalid, unknown, or malformed.
//
//          server_error
//                The authorization server encountered an unexpected
//                condition that prevented it from fulfilling the request.
//                (This error code is needed because a 500 Internal Server
//                Error HTTP status code cannot be returned to the client
//                via an HTTP redirect.)
//
//          temporarily_unavailable
//                The authorization server is currently unable to handle
//                the request due to a temporary overloading or maintenance
//                of the server.  (This error code is needed because a 503
//                Service Unavailable HTTP status code cannot be returned
//                to the client via an HTTP redirect.)
//
//          Values for the "error" parameter MUST NOT include characters
//          outside the set %x20-21 / %x23-5B / %x5D-7E.
//
//    error_description
//          OPTIONAL.  Human-readable ASCII [USASCII] text providing
//          additional information, used to assist the client developer in
//          understanding the error that occurred.
//          Values for the "error_description" parameter MUST NOT include
//          characters outside the set %x20-21 / %x23-5B / %x5D-7E.
//
//    error_uri
//          OPTIONAL.  A URI identifying a human-readable web page with
//          information about the error, used to provide the client
//          developer with additional information about the error.
//          Values for the "error_uri" parameter MUST conform to the
//          URI-reference syntax and thus MUST NOT include characters
//          outside the set %x21 / %x23-5B / %x5D-7E.
//
//    state
//          REQUIRED if a "state" parameter was present in the client
//          authorization request.  The exact value received from the
//          client.
//
//    For example, the authorization server redirects the user-agent by
//    sending the following HTTP response:
//
//    HTTP/1.1 302 Found
//    Location: https://client.example.com/cb#error=access_denied&state=xyz
func implicitGrant(w http.ResponseWriter, req *http.Request) {}
