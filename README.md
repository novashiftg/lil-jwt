# lil-jwt

lil `#![no_std]` Rust crate to parse & serialize secure JSON Web Tokens (JWT)

WARNING: the cryptography in this repository has not been independently verified, and there is no guarantee that it works. do not use this for anything critical.

example JWT serialization with HS256 signature algorithm:
```rust
use lil_json::{JsonObject, JsonValue};
use lil_jwt::{JsonWebToken, SignatureAlgorithm};

fn main() {
    let mut buffer = [0_u8; 256];
    let mut json_object = JsonObject::<10>::new();
    json_object.push_field("sub", JsonValue::String("1234567890")).unwrap();
    json_object.push_field("name", JsonValue::String("John Doe")).unwrap();
    json_object.push_field("admin", JsonValue::Boolean(true)).unwrap();
    json_object.push_field("iat", JsonValue::Number(1516239022)).unwrap();
    let n = JsonWebToken::from_claims(json_object.as_slice())
    .serialize(
        buffer.as_mut_slice(),
        lil_jwt::JwtType::Signed(SignatureAlgorithm::HS256),
        b"a-string-secret-at-least-256-bits-long"
    ).unwrap();
    assert_eq!(
        b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
        buffer.split_at(n).0
    )
}
```

JWTs can be serialized into any type that implements [`embedded_io::Write`](https://docs.rs/embedded-io/latest/embedded_io/trait.Write.html):
```rust
use std::io::stdout;

use embedded_io_adapters::std::FromStd;
use lil_json::{JsonObject, JsonValue};
use lil_jwt::{JsonWebToken, SignatureAlgorithm};

fn main() {
    let mut stdout = FromStd::new(stdout());
    let mut json_object = JsonObject::<10>::new();
    json_object.push_field("sub", JsonValue::String("1234567890")).unwrap();
    json_object.push_field("name", JsonValue::String("John Doe")).unwrap();
    json_object.push_field("admin", JsonValue::Boolean(true)).unwrap();
    json_object.push_field("iat", JsonValue::Number(1516239022)).unwrap();
    let n = JsonWebToken::from_claims(json_object.as_slice())
    .serialize(
        &mut stdout,
        lil_jwt::JwtType::Signed(SignatureAlgorithm::HS256),
        b"a-string-secret-at-least-256-bits-long"
    ).unwrap();
}

// output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30
```

the following algorithms are currently supported:
* none/unsecured
* HS256

