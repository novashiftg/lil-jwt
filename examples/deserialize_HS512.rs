#[cfg(feature = "signature")]
fn main() {
    use lil_json::{JsonField,JsonValue};
    use lil_jwt::{JsonWebToken, JwtType, SignatureAlgorithm};
    let data = b"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg";
    let mut base64buffer = [0_u8; 256];
    let claims = JsonWebToken::deserialize_claims::<10>(
        data,
        &mut base64buffer,
        JwtType::Signed(SignatureAlgorithm::HS512),
        b"a-valid-string-secret-that-is-at-least-512-bits-long-which-is-very-long",
    ).unwrap();
    let claims_slice = claims.as_slice();
    assert_eq!(4, claims_slice.len());
    assert_eq!(JsonField::new("sub", JsonValue::String("1234567890")), claims_slice[0]);
    assert_eq!(JsonField::new("name", JsonValue::String("John Doe")), claims_slice[1]);
    assert_eq!(JsonField::new("admin", JsonValue::Boolean(true)), claims_slice[2]);
    assert_eq!(JsonField::new("iat", JsonValue::Number(1516239022)), claims_slice[3]);
}

#[cfg(not(feature = "signature"))]
fn main () {
    panic!("the 'signing' feature must be enabled");
}