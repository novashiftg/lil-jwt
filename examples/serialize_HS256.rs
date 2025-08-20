#[cfg(feature = "signing")]
fn main() {
    use std::io::stdout;
    use embedded_io_adapters::std::FromStd;
    use lil_json::{JsonObject, JsonValue};
    use lil_jwt::{JsonWebToken, SignatureAlgorithm};

    let stdout = FromStd::new(stdout());
    let mut json_object = JsonObject::<10>::new();
    json_object.push_field("sub", JsonValue::String("1234567890")).unwrap();
    json_object.push_field("name", JsonValue::String("John Doe")).unwrap();
    json_object.push_field("admin", JsonValue::Boolean(true)).unwrap();
    json_object.push_field("iat", JsonValue::Number(1516239022)).unwrap();
    JsonWebToken::from_claims(json_object.as_slice())
    .serialize(
        stdout,
        lil_jwt::JwtType::Signed(SignatureAlgorithm::HS256),
        b"a-string-secret-at-least-256-bits-long"
    ).unwrap();
}

#[cfg(not(feature = "signing"))]
fn main () {
    panic!("the 'signing' feature must be enabled");
}