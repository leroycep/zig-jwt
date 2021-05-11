# JSON Web Tokens

This library implement signing and verification of [JSON Web Tokens][], or JWTs,
based on [RFC 7159][].

[json web tokens]: https://jwt.io/
[rfc 7159]: https://datatracker.ietf.org/doc/html/rfc7519

## Features

-   [x] [JWS][] tokens
-   [ ] [JWE][] tokens
-   [x] Sign
-   [x] Verify
-   [ ] iss check
-   [ ] sub check
-   [ ] aud check
-   [ ] exp check
-   [ ] nbf check
-   [ ] iat check
-   [ ] jti check
-   [ ] typ check

[JWS]: https://datatracker.ietf.org/doc/html/rfc7515
[JWE]: https://datatracker.ietf.org/doc/html/rfc7516

Encryption algorithms:

-   [x] HS256
-   [x] HS384
-   [x] HS512
-   [ ] PS256
-   [ ] PS384
-   [ ] PS512
-   [ ] RS256
-   [ ] RS384
-   [ ] RS512
-   [ ] ES256
-   [ ] ES256K
-   [ ] ES384
-   [ ] ES512
-   [ ] EdDSA
