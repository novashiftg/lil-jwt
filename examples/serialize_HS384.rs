#[cfg(feature = "signature")]
fn main() {
    use std::io::stdout;
    use embedded_io_adapters::std::FromStd;
    use lil_json::{JsonObject, JsonValue};
    use lil_jwt::{JsonWebToken, JwtType, SignatureAlgorithm};

    let stdout = FromStd::new(stdout());
    let mut json_object = JsonObject::<10>::new();
    json_object.push_field("sub", JsonValue::String("1234567890")).unwrap();
    json_object.push_field("name", JsonValue::String("John Doe")).unwrap();
    json_object.push_field("admin", JsonValue::Boolean(true)).unwrap();
    json_object.push_field("iat", JsonValue::Number(1516239022)).unwrap();
    JsonWebToken::from_claims(
        json_object.as_slice()
    ).serialize(
        stdout,
        JwtType::Signed(SignatureAlgorithm::HS384),
        b"a-valid-string-secret-that-is-at-least-384-bits-long"
    ).unwrap();
}

#[cfg(not(feature = "signature"))]
fn main () {
    panic!("the 'signing' feature must be enabled");
}