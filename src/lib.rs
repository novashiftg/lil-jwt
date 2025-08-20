#![no_std]

use core::{convert::Infallible, str::FromStr};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, DecodeError, DecodeSliceError, Engine};
use embedded_io::{ErrorType, Read, Write};

use lil_json::{parse_json_object, serialize_json_object, JsonField, JsonObject, JsonParseFailure, JsonValue, EMPTY_FIELD};

use crate::base64_writer::Base64UrlBlockEncoder;
mod base64_writer;

#[cfg(feature = "signature")]
use hmac::{Hmac, Mac};
#[cfg(feature = "signature")]
use sha2::{Sha256, Sha384, Sha512};
#[cfg(feature = "signature")]
use crate::authenticated_writer::AuthenticatedWriter;
#[cfg(feature = "signature")]
mod authenticated_writer;

#[cfg(feature = "signature")]
struct Empty{}
#[cfg(feature = "signature")]
impl ErrorType for Empty {
    type Error = Infallible;
}
#[cfg(feature = "signature")]
impl Write for Empty {
    fn write(& mut self, data: &[u8]) -> Result<usize, <Self as ErrorType>::Error> { Ok(data.len()) }
    fn flush(&mut self) -> Result<(), Self::Error> { Ok(()) }
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum SignatureAlgorithm {
    HS256,
    HS384,
    HS512,
}

impl core::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str(Self::as_static_string(&self))
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = ();
    fn from_str(string: &str) -> Result<Self, <Self as FromStr>::Err> {
        match Self::from_string(string) {
            Some(s) => Ok(s),
            None => Err(())
        }
    }
}

impl SignatureAlgorithm {
    const fn as_static_string(&self) -> &'static str {
        match self {
            SignatureAlgorithm::HS256 => "HS256",
            SignatureAlgorithm::HS384 => "HS384",
            SignatureAlgorithm::HS512 => "HS512",
        }
    }
    fn from_string(string: &str) -> Option<Self> {
        return Some(match string {
            "HS256" => SignatureAlgorithm::HS256,
            "HS384" => SignatureAlgorithm::HS384,
            "HS512" => SignatureAlgorithm::HS512,
            _ => return None,
        })
    }
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum EncryptionAlgorithm {
    // TODO
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum JwtType {
    Unsecured,
    #[cfg(feature = "signature")]
    Signed(SignatureAlgorithm),
    Encrypted(EncryptionAlgorithm)
}

impl JwtType {
    const fn as_static_string(&self) -> &'static str {
        match self {
            Self::Unsecured => "none",
            #[cfg(feature = "signature")]
            Self::Signed(signature_algorithm) => signature_algorithm.as_static_string(),
            Self::Encrypted(_) => todo!(),
        }
    }
    fn from_string(string: &str) -> Option<Self> {
        if string == "none" {
            return Some(Self::Unsecured);
        }
        #[cfg(feature = "signature")]
        if let Some(s) = SignatureAlgorithm::from_string(string) {
            return Some(JwtType::Signed(s))
        }
        return None;
    }
}

#[derive(Debug)]
pub enum JwtParseFailure {
    NotEnoughDots,
    InvalidBase64Url(DecodeError),
    Base64BufferTooSmall,
    InvalidSignature,
    // InvalidEncryption,
    AlgorithmMismatch,
    IncorrectHeader,
    InvalidHeader(JsonParseFailure),
    InvalidClaims(JsonParseFailure),
}

pub struct JsonWebToken<'a> {
    claims: &'a [JsonField<'a,'a>],
}

impl<'a> JsonWebToken<'a> {

    pub fn from_claims(claims: &'a [JsonField<'a,'a>]) -> Self {
        Self { claims }
    }

    pub fn serialize<T: Write>(&self, output: T, algorithm: JwtType, secret: &[u8]) -> Result<usize,T::Error> {
        serialize_jwt(output, self.claims, &algorithm, secret)
    }

    pub fn deserialize_claims<const MAX_CLAIMS: usize>(data: &'a[u8], base64buffer: &'a mut [u8], algorithm: JwtType, secret: &[u8]) -> Result<JsonObject<'a,MAX_CLAIMS>,JwtParseFailure> {
        let mut claims_buffer = [EMPTY_FIELD; MAX_CLAIMS];
        let num_claims = deserialize_jwt(data, &mut claims_buffer, &algorithm, secret, base64buffer)?;
        let mut ret = JsonObject::<MAX_CLAIMS>::new();
        for claim in claims_buffer.split_at(num_claims).0 {
            ret.push(*claim).expect("ret holds MAX_CLAIMS");
        }
        Ok(ret)
    }
}

const fn get_jose_header(include_typ_header: bool, algorithm: &JwtType) -> JsonObject<'static,2> {
    let mut ret = JsonObject::<2>::new();
    match ret.push_field("alg", JsonValue::String(algorithm.as_static_string())) {
        Ok(()) => {},
        Err(()) => unreachable!(),
    }
    if include_typ_header {
        match ret.push_field("typ", JsonValue::String("JWT")) {
            Ok(()) => {},
            Err(()) => unreachable!(),
        }
    }
    ret
}

fn split_jwt_parts(data: &[u8]) -> Result<(&[u8],&[u8],&[u8]),JwtParseFailure>  {
    let mut dot_indices = data
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| if b == b'.' { Some(i) } else { None });
    let first_dot = match dot_indices.next() {
        Some(f) => f,
        None => return Err(JwtParseFailure::NotEnoughDots),
    };
    let second_dot = match dot_indices.next() {
        Some(s) => s,
        None => return Err(JwtParseFailure::NotEnoughDots),
    };
    let (header_slice, after_header) = data.split_at(first_dot);
    let (body_with_dot, signature_with_dot) = after_header.split_at(second_dot - first_dot);
    let body_slice = body_with_dot.split_at(1).1;
    let signature_slice = signature_with_dot.split_at(1).1;
    Ok((header_slice,body_slice,signature_slice))
}

fn verify_jose_header(header_fields: &[JsonField<'_,'_>], expected_algorithm: &JwtType) -> Result<(),JwtParseFailure> {
    let mut alg_header: Option<&str> = None;
    for header_field in header_fields {
        if header_field.key == "alg" {
            match header_field.value {
                JsonValue::String(alg_value) => {
                    match alg_header.replace(alg_value) {
                        None => {},
                        Some(_duplicate_alg_header) => return Err(JwtParseFailure::IncorrectHeader),
                    }
                },
                _ => return Err(JwtParseFailure::IncorrectHeader)
            }
        }
    }
    let alg_header_value = match alg_header {
        None => return Err(JwtParseFailure::IncorrectHeader),
        Some(v) => v,
    };
    if alg_header_value != expected_algorithm.as_static_string() {
        return Err(JwtParseFailure::AlgorithmMismatch);
    }
    Ok(())
}

pub fn deserialize_jwt<'a>(data: &'a [u8], claims_buffer: &mut [JsonField<'a,'a>], algorithm: &JwtType, secret: &[u8], base64buffer: &'a mut [u8]) -> Result<usize,JwtParseFailure> {
    let (header_b64,body_b64,signature_b64) = split_jwt_parts(data)?;
    match algorithm {
        JwtType::Unsecured => {
             let header_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(header_b64, base64buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            let (decoded_header,remaining_base64_buffer) = base64buffer.split_at_mut(header_decoded_end);
            let body_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(body_b64, remaining_base64_buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            let decoded_claims = remaining_base64_buffer.split_at(body_decoded_end).0;
            let mut header_buffer = [EMPTY_FIELD; 5];
            let (_num_data,num_header_fields) = match parse_json_object(decoded_header, &mut header_buffer) {
                Ok(n) => n,
                Err(j) => return Err(JwtParseFailure::InvalidHeader(j)),
            };
            verify_jose_header(header_buffer.split_at(num_header_fields).0, algorithm)?;
            let num_claims = match parse_json_object(decoded_claims, claims_buffer) {
                Ok((_num_bytes,n)) => n,
                Err(j) => return Err(JwtParseFailure::InvalidClaims(j)),
            };
            Ok(num_claims)
        },
        #[cfg(feature = "signature")]
        JwtType::Signed(SignatureAlgorithm::HS256) => {
            let digest = Hmac::<Sha256>::new_from_slice(secret).expect("invalid HS256 secret");
            let mac = digest
            .chain_update(header_b64)
            .chain_update(b".")
            .chain_update(body_b64)
            .finalize()
            .into_bytes();
            let signature_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(signature_b64, base64buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            if signature_decoded_end != 32 || mac.as_slice() != base64buffer.split_at(signature_decoded_end).0 {
                return Err(JwtParseFailure::InvalidSignature);
            }
            let header_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(header_b64, base64buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            let (decoded_header,remaining_base64_buffer) = base64buffer.split_at_mut(header_decoded_end);
            let body_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(body_b64, remaining_base64_buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            let decoded_claims = remaining_base64_buffer.split_at(body_decoded_end).0;
            let mut header_buffer = [EMPTY_FIELD; 5];
            let (_num_data,num_header_fields) = match parse_json_object(decoded_header, &mut header_buffer) {
                Ok(n) => n,
                Err(j) => return Err(JwtParseFailure::InvalidHeader(j)),
            };
            verify_jose_header(header_buffer.split_at(num_header_fields).0, algorithm)?;
            let num_claims = match parse_json_object(decoded_claims, claims_buffer) {
                Ok((_num_bytes,n)) => n,
                Err(j) => return Err(JwtParseFailure::InvalidClaims(j)),
            };
            Ok(num_claims)
        },
        #[cfg(feature = "signature")]
        JwtType::Signed(SignatureAlgorithm::HS384) => {
            let digest = Hmac::<Sha384>::new_from_slice(secret).expect("invalid HS256 secret");
            let mac = digest
            .chain_update(header_b64)
            .chain_update(b".")
            .chain_update(body_b64)
            .finalize()
            .into_bytes();
            let signature_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(signature_b64, base64buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            if signature_decoded_end != 48 || mac.as_slice() != base64buffer.split_at(signature_decoded_end).0 {
                return Err(JwtParseFailure::InvalidSignature);
            }
            todo!()
        },
        #[cfg(feature = "signature")]
        JwtType::Signed(SignatureAlgorithm::HS512) => {
            let digest = Hmac::<Sha512>::new_from_slice(secret).expect("invalid HS256 secret");
            let mac = digest
            .chain_update(header_b64)
            .chain_update(b".")
            .chain_update(body_b64)
            .finalize()
            .into_bytes();
            let signature_decoded_end = match BASE64_URL_SAFE_NO_PAD.decode_slice(signature_b64, base64buffer) {
                Ok(n) => n,
                Err(DecodeSliceError::OutputSliceTooSmall) => return Err(JwtParseFailure::Base64BufferTooSmall),
                Err(DecodeSliceError::DecodeError(e)) => return Err(JwtParseFailure::InvalidBase64Url(e)),
            };
            if signature_decoded_end != 64 || mac.as_slice() != base64buffer.split_at(signature_decoded_end).0 {
                return Err(JwtParseFailure::InvalidSignature);
            }
            todo!()
        },
        _ => todo!()
    }
}

fn serialize_object_base64<T: embedded_io::Write>(output: T, claims: &[JsonField<'_,'_>]) -> Result<usize,T::Error> {
    let mut body_encoder = Base64UrlBlockEncoder::new(output);
    serialize_json_object(&mut body_encoder, claims)?;
    body_encoder.finalize(false)
}

fn serialize_slice_base64<T: embedded_io::Write>(output: T, slice: &[u8]) -> Result<usize,T::Error> {
    let mut slice_encoder = Base64UrlBlockEncoder::new(output);
    slice_encoder.write_all(slice)?;
    slice_encoder.finalize(false)
}

pub fn serialize_jwt<T: embedded_io::Write>(mut output: T, claims: &[JsonField<'_,'_>], algorithm: &JwtType, secret: &[u8]) -> Result<usize,T::Error> {
    let header = get_jose_header(algorithm != &JwtType::Unsecured, algorithm);
    let mut ret = 0;
    match algorithm {
        JwtType::Unsecured => {
            ret += serialize_object_base64(&mut output, header.as_slice())?;
            output.write_all(b".")?;
            ret += 1;
            ret += serialize_object_base64(&mut output, claims)?;
            output.write_all(b".")?;
            ret += 1;
            Ok(ret)
        },
        #[cfg(feature = "signature")]
        JwtType::Signed(SignatureAlgorithm::HS256) => {
            // assert!(secret.len() >= 256);
            let digest = Hmac::<Sha256>::new_from_slice(secret).expect("invalid HS256 secret");
            let mut authenticated_writer = AuthenticatedWriter::new(&mut output, digest);
            ret += serialize_object_base64(&mut authenticated_writer, header.as_slice()).unwrap();
            authenticated_writer.write_all(b".")?;
            ret += 1;
            ret += serialize_object_base64(&mut authenticated_writer, claims)?;
            let mac = authenticated_writer.finalize_mac();
            output.write_all(b".")?;
            ret += 1;
            ret += serialize_slice_base64(&mut output, &mac.into_bytes())?;
            Ok(ret)
        },
        #[cfg(feature = "signature")]
        JwtType::Signed(SignatureAlgorithm::HS384) => {
            // assert!(secret.len() >= 384);
            let digest = Hmac::<Sha384>::new_from_slice(secret).expect("invalid HS384 secret");
            let mut authenticated_writer = AuthenticatedWriter::new(&mut output, digest);
            ret += serialize_object_base64(&mut authenticated_writer, header.as_slice()).unwrap();
            authenticated_writer.write_all(b".")?;
            ret += 1;
            ret += serialize_object_base64(&mut authenticated_writer, claims)?;
            let mac = authenticated_writer.finalize_mac();
            output.write_all(b".")?;
            ret += 1;
            ret += serialize_slice_base64(&mut output, &mac.into_bytes())?;
            Ok(ret)
        },
        #[cfg(feature = "signature")]
        JwtType::Signed(SignatureAlgorithm::HS512) => {
            // assert!(secret.len() >= 512);
            let digest = Hmac::<Sha512>::new_from_slice(secret).expect("invalid HS512 secret");
            let mut authenticated_writer = AuthenticatedWriter::new(&mut output, digest);
            ret += serialize_object_base64(&mut authenticated_writer, header.as_slice()).unwrap();
            authenticated_writer.write_all(b".")?;
            ret += 1;
            ret += serialize_object_base64(&mut authenticated_writer, claims)?;
            let mac = authenticated_writer.finalize_mac();
            output.write_all(b".")?;
            ret += 1;
            ret += serialize_slice_base64(&mut output, &mac.into_bytes())?;
            Ok(ret)
        },
        JwtType::Encrypted(_) => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

     #[test]
    fn test_serialize_unsecured_empty() {
        let mut buffer = [0_u8; 256];
        let n = JsonWebToken::from_claims(&[]).serialize(buffer.as_mut_slice(), JwtType::Unsecured, &[]).unwrap();
        assert_eq!(b"eyJhbGciOiJub25lIn0.e30.", buffer.split_at(n).0)
    }

}