#![allow(clippy::missing_safety_doc)]
use super::error::ParserError;
use super::FromBytes;
use crate::zxformat::{pageString, Writer};

use crate::bolos::{sha256, SHA256_LEN};
use core::{fmt::Write, str};
use hex::encode_to_slice;

const MAX_BASE64_HEADER_LEN: usize = 250;

fn decode_data(input: &[u8], output: &mut [u8]) -> Result<usize, ParserError> {
    let estimate_len = (input.len() + 3) / 4;
    let estimate_len = estimate_len * 3;

    if output.len() < estimate_len {
        return Err(ParserError::UnexpectedBufferEnd);
    }

    // TODO: Add new error for this decoding error
    base64::decode_config_slice(input, base64::URL_SAFE, output)
        .map_err(|_| ParserError::UnexpectedType)
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Jwt<'a> {
    jwt_data: &'a [u8],
}

impl<'b> FromBytes<'b> for Jwt<'b> {
    #[inline(never)]
    fn from_bytes_into(
        data: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;

        Self::parse_header_payload(data)?;

        let out_ptr = out.as_mut_ptr();

        // Initialize the jwt_data field
        unsafe {
            addr_of_mut!((*out_ptr).jwt_data).write(data);
        }

        // Return empty slice as we've consumed everything we need
        Ok(&data[0..0])
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct JwtHeader<'a>(&'a [u8]);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, serde::Deserialize)]
pub struct Header<'a> {
    typ: &'a str,
    alg: &'a str,
}

// We would also need to implement FromBytes for JwtHeader if needed
impl<'b> FromBytes<'b> for JwtHeader<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;

        if !input.is_ascii() {
            return Err(nom::Err::Error(ParserError::UnexpectedType));
        }

        let mut header_bytes = [0u8; MAX_BASE64_HEADER_LEN];

        let len = match decode_data(input, header_bytes.as_mut()) {
            Ok(len) => len,
            Err(e) => return Err(nom::Err::Error(e)),
        };

        let header: Header = match serde_json_core::from_slice(&header_bytes[..len]) {
            Ok((h, _)) => h,
            Err(_) => return Err(nom::Err::Error(ParserError::InvalidJwt)),
        };

        if !header.is_valid() {
            return Err(nom::Err::Error(ParserError::InvalidJwt));
        }

        // Get a pointer to the uninitialized memory
        let out_ptr = out.as_mut_ptr();

        // Initialize the underlying slice
        unsafe {
            addr_of_mut!((*out_ptr).0).write(input);
        }

        // Return empty slice as we've consumed everything we need
        Ok(&[])
    }
}

impl Header<'_> {
    fn is_valid(&self) -> bool {
        // "JWT"
        let typ = [b'J', b'W', b'T'];
        // "ES256K"
        let algo = [b'E', b'S', b'2', b'5', b'6', b'K'];
        self.typ.as_bytes() == typ && self.alg.as_bytes() == algo
    }
}

impl<'a> JwtHeader<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if !data.is_ascii() {
            return Err(ParserError::UnexpectedType);
        }

        let mut header_bytes = [0u8; MAX_BASE64_HEADER_LEN];

        let len = decode_data(data, header_bytes.as_mut())?;
        let header: Header = serde_json_core::from_slice(&header_bytes[..len])
            .map(|(h, _)| h)
            .map_err(|_| ParserError::InvalidJwt)?;

        if !header.is_valid() {
            return Err(ParserError::InvalidJwt);
        }
        Ok(Self(data))
    }
}

impl<'a> Jwt<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        let _ = Self::parse_header_payload(data)?;
        Ok(Self { jwt_data: data })
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        let _ = Self::parse_header_payload(data)?;
        self.jwt_data = data;
        Ok(())
    }

    fn parse_header_payload(data: &'a [u8]) -> Result<(&'a [u8], JwtHeader<'a>), ParserError> {
        // Only ascii values are valid for json web token
        if !data.is_ascii() {
            return Err(ParserError::InvalidJwt);
        }

        let mut jwt_parts = data.split(|byte| *byte == b'.');
        let header_data = jwt_parts.next().ok_or(ParserError::InvalidJwt)?;

        let header = JwtHeader::from_bytes(header_data)?;

        let payload = jwt_parts.next().ok_or(ParserError::InvalidJwt)?;

        if jwt_parts.next().is_some() {
            return Err(ParserError::InvalidJwt);
        }

        Ok((payload, header))
    }

    pub fn is_jwt(data: &'a [u8]) -> bool {
        Self::parse_header_payload(data).is_ok()
    }

    pub fn get_hash(&self, output: &mut [u8; SHA256_LEN]) {
        // wont panic as output is the right len
        sha256(self.jwt_data, output.as_mut()).unwrap()
    }

    pub fn num_items(&self) -> u8 {
        // only show the hash of the input
        1
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx > 0 {
            return Err(ParserError::DisplayIdxOutOfRange);
        }

        let mut writer_key = Writer::new(out_key);

        writer_key
            .write_str("JWT hash:")
            .map_err(|_| ParserError::UnexpectedBufferEnd)?;

        let mut out_data = [0u8; SHA256_LEN];
        self.get_hash(&mut out_data);
        // hex encode the hash
        let mut hash_str = [0u8; SHA256_LEN * 2];
        encode_to_slice(out_data.as_ref(), hash_str.as_mut())
            .map_err(|_| ParserError::UnexpectedError)?;
        pageString(out_value, hash_str.as_ref(), page_idx)
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use std::fmt::Display;
    use std::format;
    use std::println;
    use std::string::String;
    use std::string::ToString;

    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct Header {
        typ: &'static str,
        alg: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        other: Option<String>,
    }

    impl Default for Header {
        fn default() -> Self {
            Self {
                typ: "JWT",
                alg: "ES256K",
                other: None,
            }
        }
    }

    impl Header {
        fn with_other(other: Option<String>) -> Self {
            Self {
                other,
                ..Default::default()
            }
        }
    }

    impl Display for Header {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let header =
                base64::encode_config(serde_json::to_string(&self).unwrap(), base64::URL_SAFE);
            write!(f, "{}", header)
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct Payload {
        issued_at: f64,
        challenge: String,
        issuer: String,
        blockchainid: String,
    }

    impl Display for Payload {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let payload =
                base64::encode_config(serde_json::to_string(self).unwrap(), base64::URL_SAFE);
            write!(f, "{}", payload)
        }
    }

    impl Payload {
        fn new() -> Self {
            let issued_at = 1440713414.85;
            let challenge = "7cd9ed5e-bb0e-49ea-a323-f28bde3a0549".to_string();
            let issuer="xpub661MyMwAqRbcFQVrQr4Q4kPjaP4JjWaf39fBVKjPdK6oGBayE46GAmKzo5UDPQdLSM9DufZiP8eauy56XNuHicBySvZp7J5wsyQVpi2axzZ".to_string();
            let blockchainid = "ryan".to_string();
            Self {
                issued_at,
                challenge,
                issuer,
                blockchainid,
            }
        }
    }

    fn create_jwt(header: Header, payload: Payload) -> String {
        format!("{}.{}", header, payload)
    }

    #[test]
    fn basic_jwt() {
        let header = Header::default();
        println!("{}", serde_json::to_string(&header).unwrap());
        let payload = Payload::new();

        let jwt = create_jwt(header, payload);
        println!("jwt: {}", jwt);

        Jwt::from_bytes(jwt.as_bytes()).unwrap();
    }
}
