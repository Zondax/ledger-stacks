#![allow(clippy::missing_safety_doc)]

use crate::{
    bolos::c_zemu_log_stack,
    zxformat::{pageString, Writer},
};
use core::fmt::Write;

use nom::bytes::complete::tag;

use super::{error::ParserError, Tuple, Value, ValueId, MAX_DEPTH};
use crate::bolos::{sha256, SHA256_LEN};
use hex::encode_to_slice;

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Domain<'a>(Value<'a>);

impl<'a> Domain<'a> {
    // number of fields in the Domain clarity tuple
    const LEN: usize = 3;

    pub fn from_bytes(data: &'a [u8]) -> Result<(&'a [u8], Self), nom::Err<ParserError>> {
        let (rem, value) = Value::from_bytes::<MAX_DEPTH>(data)?;

        // Domain is a tuple with 3 elements
        let tuple = value
            .tuple()
            .ok_or(ParserError::parser_invalid_structured_msg)?;

        let mut items = 0;
        for (key, value) in tuple.iter() {
            let value_id = value.value_id();
            match (key.name(), value_id) {
                (b"name", ValueId::StringAscii) => {}
                (b"version", ValueId::StringAscii) => {}
                (b"chain-id", ValueId::UInt) => {}
                _ => return Err(ParserError::parser_invalid_structured_msg.into()),
            }
            items += 1;
        }

        if items != tuple.num_elements() || items != Self::LEN {
            return Err(ParserError::parser_invalid_structured_msg.into());
        }

        Ok((rem, Self(value)))
    }

    fn tuple(&'a self) -> Tuple<'a> {
        // wont panic as this was checked by the parser
        self.0.tuple().unwrap()
    }

    // This returns the domain bytes
    // which is used to get the domain_hash
    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }

    pub fn num_items(&self) -> usize {
        3
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        use numtoa::NumToA;

        let mut buff = [0; 39];

        if let Some((key, value)) = self.tuple().iter().nth(display_idx as usize) {
            out_key[0..key.name().len()].copy_from_slice(key.name());

            let id = value.value_id();

            if id == ValueId::UInt {
                // wont panic as this was checked by the parser
                let chain_id = value.uint().unwrap();
                let num = chain_id.numtoa_str(10, &mut buff).as_bytes();

                pageString(out_value, num, page_idx)
            } else {
                let string = value.string_ascii().unwrap();

                pageString(out_value, string.content(), page_idx)
            }
        } else {
            Err(ParserError::parser_unexpected_number_items)
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct StructuredMsg<'a>(&'a [u8]);

impl<'a> StructuredMsg<'a> {
    const PREFIX_LEN: usize = 6;

    pub fn from_bytes(input: &'a [u8]) -> Result<Self, ParserError> {
        c_zemu_log_stack("StructuredMsg::from_bytes\x00");
        Self::verify(input)?;

        Ok(Self(input))
    }

    pub fn read(&mut self, input: &'a [u8]) -> Result<(), ParserError> {
        c_zemu_log_stack("StructuredMsg::read\x00");

        Self::verify(input)?;
        self.0 = input;
        Ok(())
    }

    pub fn verify(input: &'a [u8]) -> Result<(), ParserError> {
        let rem = Self::parse_prefix(input)?;
        // parse domain
        let (msg, _) = Domain::from_bytes(rem)?;

        // validate msg, but here we can be limiting the complexity
        // of the msg we can parse as the device has limited resources.
        // lets evaluate if a recursion limit of MAX_DEPTH is good for
        // general purposed structured data
        Self::validate(msg)?;

        Ok(())
    }

    // Check for the header for this type of structured data
    pub fn is_msg(data: &'a [u8]) -> bool {
        Self::has_prefix(data)
    }

    fn prefix() -> [u8; StructuredMsg::PREFIX_LEN] {
        let prefix = b"SIP018";
        let mut p = [0; Self::PREFIX_LEN];
        p.copy_from_slice(&prefix[..]);
        p
    }

    fn parse_prefix(data: &'a [u8]) -> Result<&'a [u8], nom::Err<ParserError>> {
        let prefix = Self::prefix();
        tag(prefix)(data).map(|(rem, _)| rem)
    }

    // Checks if the input data comes with a prefix as specified by SIP018
    fn has_prefix(data: &'a [u8]) -> bool {
        Self::parse_prefix(data).is_ok()
    }

    fn validate(data: &[u8]) -> Result<(), ParserError> {
        let (rem, _) = Value::from_bytes::<MAX_DEPTH>(data)?;
        if !rem.is_empty() {
            return Err(ParserError::parser_unexpected_value);
        }
        Ok(())
    }

    // returns the message content
    fn msg(&self) -> &[u8] {
        // skip header and domain
        let data = &self.0[Self::PREFIX_LEN..];
        // read out the domain, wont panic as data was previously parsed
        Domain::from_bytes(data).map(|(msg, _)| msg).unwrap()
    }

    fn domain(&self) -> Domain<'a> {
        // skip header and domain
        let data = &self.0[Self::PREFIX_LEN..];
        // read out the domain, wont panic as data was previously parsed
        Domain::from_bytes(data).map(|(_, d)| d).unwrap()
    }

    #[inline(never)]
    pub fn get_hash(&self, out: &mut [u8]) -> Result<(), ParserError> {
        if out.len() < SHA256_LEN {
            return Err(ParserError::parser_unexpected_buffer_end);
        }
        // get prefix
        let prefix = Self::prefix();
        let prefix_len = prefix.len();
        // construct buffer to hold prefix, domain_hash and msg_hash
        let mut to_hash = [0; StructuredMsg::PREFIX_LEN + SHA256_LEN * 2];
        // copy prefix
        to_hash[..prefix_len].copy_from_slice(&prefix[..]);

        // 1. get domain hash
        // wont panic as out has the right len
        let domain = self.domain();
        sha256(
            domain.bytes(),
            &mut to_hash[prefix_len..prefix_len + SHA256_LEN],
        )
        .unwrap();
        // 1. get msg hash
        // wont panic as out has the right len
        let len = to_hash.len();
        sha256(self.msg(), &mut to_hash[len - SHA256_LEN..]).unwrap();

        // compute msg hash
        // wont panic as out is SHA256_LEN bytes len
        sha256(&to_hash[..], &mut out[0..SHA256_LEN]).unwrap();

        Ok(())
    }

    pub fn num_items(&self) -> u8 {
        // domain name, version, chain_id and msg_hash
        self.domain().num_items() as u8 + 1
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        match display_idx {
            0..=2 => {
                let mut domain = self.domain();
                domain.get_item(display_idx, out_key, out_value, page_idx)
            }
            3 => {
                let mut writer_key = Writer::new(out_key);
                writer_key
                    .write_str("Message Hash")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;

                // 1. get prefix hash
                let mut hash = [0; SHA256_LEN];
                // wont panic as we are passing an output buffer longer enough
                self.get_hash(&mut hash).unwrap();

                // buffer to store the hex hash
                let mut hex = [0; SHA256_LEN * 2];

                encode_to_slice(&hash[..], &mut hex[..])
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;

                pageString(out_value, &hex[..], page_idx)
            }

            _ => Err(ParserError::parser_unexpected_number_items),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn parse_bad_domain_name() {
        let input = "0c0000000308636861696e2d69640100000000000000000000000000025983016e0d00000006537461636b730776657273696f6e0d00000005312e302e30";
        let bytes = hex::decode(input).unwrap();
        let msg = StructuredMsg::from_bytes(&bytes);
        assert!(msg.is_err());
    }

    #[test]
    fn parse_bad_domain_name_type() {
        let input = "0c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0d00000005312e302e30";
        let bytes = hex::decode(input).unwrap();
        let msg = StructuredMsg::from_bytes(&bytes);
        assert!(msg.is_err());
    }

    #[test]
    fn parse_structured_msg_string() {
        let input = "5349503031380c0000000308636861696e2d69640100000000000000000000000000025903046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300d000001634c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742e204d616563656e61732066617563696275732074656c6c7573206d6f6c657374696520696163756c697320766976657272612e2050686173656c6c75732073697420616d657420706f727461207175616d2c2065752067726176696461207175616d2e2050686173656c6c757320636f6d6d6f646f20656c656966656e64207175616d2c206567657420696e74657264756d20617263752074656d70757320696e2e2050686173656c6c7573206163206d65747573206e6962682e20457469616d206e6f6e20656e696d206c616375732e204e616d2074656d706f72206c6967756c61206d692c206e6f6e20636f6e736571756174206d6920736f64616c65732069642e2051756973717565206672696e67696c6c61206e6f6e2065726f7320616320766976657272612e";
        let bytes = hex::decode(input).unwrap();
        let mut msg = StructuredMsg::from_bytes(&bytes).unwrap();
        msg.read(&bytes).unwrap();
    }

    #[test]
    fn parse_complex_structured_msg() {
        let input = "5349503031380c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c00000008016100ffffffffffffffffffffffffffffffff01620200000008616263646566676808636861696e2d69640100000000000000000000000000000001016d0b0000000400ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffff046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30057475706c650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0d00000005312e302e30067475706c65320c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000020c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30";
        let bytes = hex::decode(input).unwrap();
        let mut msg = StructuredMsg::from_bytes(&bytes).unwrap();
        msg.read(&bytes).unwrap();
    }
}
