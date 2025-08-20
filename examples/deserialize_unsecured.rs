use lil_json::{JsonField,JsonValue};
use lil_jwt::{JsonWebToken, JwtType};

fn main() {
    let data = b"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTczNjI5MjEyNH0.";
    let mut base64buffer = [0_u8; 256];
    let claims = JsonWebToken::deserialize_claims::<10>(
        data,
        &mut base64buffer,
        JwtType::Unsecured,
        b"ignored",
    ).unwrap();
    let claims_slice = claims.as_slice();
    assert_eq!(4, claims_slice.len());
    assert_eq!(JsonField::new("sub", JsonValue::String("1234567890")), claims_slice[0]);
    assert_eq!(JsonField::new("name", JsonValue::String("John Doe")), claims_slice[1]);
    assert_eq!(JsonField::new("admin", JsonValue::Boolean(true)), claims_slice[2]);
    assert_eq!(JsonField::new("iat", JsonValue::Number(1736292124)), claims_slice[3]);
}