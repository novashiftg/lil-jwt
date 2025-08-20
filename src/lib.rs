use core::str::FromStr;

use embedded_io::Write;
use hmac::{Hmac, Mac};
use lil_json::{serialize_json_object, JsonField, JsonObject, JsonParseFailure, JsonValue};
use sha2::{Sha256, Sha384, Sha512};

use crate::{authenticated_writer::AuthenticatedWriter, base64_writer::Base64UrlBlockEncoder};

mod base64_writer;
mod authenticated_writer;

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
pub enum JwtAlgorithm {
    Unsecured,
    Signed(SignatureAlgorithm),
    Encrypted(EncryptionAlgorithm)
}

impl JwtAlgorithm {
    const fn as_static_string(&self) -> &'static str {
        match self {
            Self::Unsecured => "none",
            Self::Signed(signature_algorithm) => signature_algorithm.as_static_string(),
            Self::Encrypted(_) => todo!(),
        }
    }
    fn from_string(string: &str) -> Option<Self> {
        if string == "none" {
            return Some(Self::Unsecured);
        } else if let Some(s) = SignatureAlgorithm::from_string(string) {
            return Some(JwtAlgorithm::Signed(s))
        }
        // TODO: encryption algorithms
        return None;
    }
}

// pub struct JwtSerializationConfig {
//     include_typ_in_header: bool,
// }

// impl Default for JwtSerializationConfig {
//     fn default() -> Self { 
//         Self { include_typ_in_header: true }
//      }
// }

// pub struct JwtDeserializationConfig {
//     require_typ_in_header: bool,
// }

pub enum JwtParseFailure {
    NotEnoughDots,
    NonBase64UrlData,
    InvalidSignature,
    // InvalidEncryption,
    AlgorithmMismatch,
    IncorrectHeader,
    InvalidHeader(JsonParseFailure),
    InvalidClaims(JsonParseFailure),
}

pub struct JsonWebToken<'a> {
    extra_header_fields: Option<&'a [JsonField<'a,'a>]>,
    claims: &'a [JsonField<'a,'a>],
}

impl<'a> JsonWebToken<'a> {

    pub fn from_claims(claims: &'a [JsonField<'a,'a>]) -> Self {
        Self { claims, extra_header_fields: None }
    }

    pub fn serialize<T: Write>(&self, output: T, algorithm: JwtAlgorithm, secret: &[u8]) -> Result<usize,T::Error> {
        serialize_jwt(output, self.claims, &algorithm, secret)
    }

    pub fn deserialize_claims<const MAX_CLAIMS: usize>(data: &'a[u8]) -> Result<(usize,JsonObject<'a,MAX_CLAIMS>),JwtParseFailure> {
        todo!()
    }
}

const fn get_jose_header(include_typ_header: bool, algorithm: &JwtAlgorithm) -> JsonObject<'static,2> {
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
    let (body_slice, after_claims) = after_header.split_at(first_dot - second_dot + 1); // skip the dot
    let signature_slice = after_claims.split_at(1).1; // skip the dot
    Ok((header_slice,body_slice,signature_slice))
}

fn parse_jwt<'a, const MAX_CLAIMS: usize>(data: &'a [u8]) -> Result<(usize,JsonObject<'a,MAX_CLAIMS>),JwtParseFailure> {
    todo!()
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

fn serialize_jwt<T: embedded_io::Write>(mut output: T, claims: &[JsonField<'_,'_>], algorithm: &JwtAlgorithm, secret: &[u8]) -> Result<usize,T::Error> {
    let header = get_jose_header(algorithm != &JwtAlgorithm::Unsecured, algorithm);
    let mut ret = 0;
    match algorithm {
        JwtAlgorithm::Unsecured => {
            ret += serialize_object_base64(&mut output, header.as_slice())?;
            output.write_all(b".")?;
            ret += 1;
            ret += serialize_object_base64(&mut output, claims)?;
            output.write_all(b".")?;
            ret += 1;
            Ok(ret)
        },
        JwtAlgorithm::Signed(SignatureAlgorithm::HS256) => {
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
        JwtAlgorithm::Signed(SignatureAlgorithm::HS384) => {
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
        JwtAlgorithm::Signed(SignatureAlgorithm::HS512) => {
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
        _ => todo!(),
    }
}


    // fn serialize<T: embedded_io::Write>(&self, signature: SignatureAlgorithm, secret: &[u8], mut output: T) -> Result<usize, T::Error> {
    //     // let body_slice = self.claims.fields.split_at(self.claims.num_fields).0;
    //     let header = signature.get_header_base64url();
    //     match signature {
    //         SignatureAlgorithm::Unsecured => {
    //             let mut ret = 0;
    //             output.write_all(header.as_bytes())?;
    //             ret += header.len();
    //             output.write_all(b".")?;
    //             ret += 1;
    //             let mut encoder = Base64BlockEncoder::new(&mut output);
    //             write_json_map(&mut encoder, self.claims.as_slice())?;
    //             let body_length = encoder.finalize(false)?.0;
    //             ret += body_length;
    //             output.write_all(b".")?;
    //             ret += 1;
    //             Ok(ret)
    //         },
    //         SignatureAlgorithm::HS256 => {
    //             let mut authenticator = AuthenticatedWriter::new(&mut output, HmacSha256::new_from_slice(secret).unwrap());
    //             let mut ret = 0;
    //             authenticator.write_all(header.as_bytes())?;
    //             ret += header.len();
    //             authenticator.write_all(b".")?;
    //             ret += 1;
    //             let mut body_encoder = Base64BlockEncoder::new(&mut authenticator);
    //             write_json_map(&mut body_encoder, self.claims.as_slice())?;
    //             let body_length = body_encoder.finalize(false)?.0;
    //             ret += body_length;
    //             let signature_out = authenticator.finalize_mac();
    //             output.write_all(b".")?;
    //             ret += 1;
    //             let mut sig_writer = Base64BlockEncoder::new(&mut output);
    //             sig_writer.write_all(&signature_out.into_bytes())?;
    //             let signature_length = sig_writer.finalize(false)?.0;
    //             ret += signature_length;
    //             Ok(ret)
    //         },
    //     }
    // }
