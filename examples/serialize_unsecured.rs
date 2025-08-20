use std::io::stdout;
use embedded_io_adapters::std::FromStd;
use lil_json::{JsonObject, JsonValue};
use lil_jwt::JsonWebToken;

fn main() {
    let stdout = FromStd::new(stdout());
    let mut json_object = JsonObject::<10>::new();
    json_object.push_field("sub", JsonValue::String("1234567890")).unwrap();
    json_object.push_field("name", JsonValue::String("John Doe")).unwrap();
    json_object.push_field("admin", JsonValue::Boolean(true)).unwrap();
    json_object.push_field("iat", JsonValue::Number(1736292124)).unwrap();
    JsonWebToken::from_claims(json_object.as_slice())
    .serialize(
        stdout,
        lil_jwt::JwtType::Unsecured,
        b"ignored",
    ).unwrap();
}