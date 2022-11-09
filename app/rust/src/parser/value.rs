use core::convert::TryFrom;

use nom::{
    bytes::complete::take,
    number::complete::{be_u32, le_u8},
};

use crate::{bolos::c_zemu_log_stack, check_canary};

use super::{ClarityName, ContractPrincipal, ParserError, StandardPrincipal};

// Big ints size in bytes
pub const BIG_INT_SIZE: usize = core::mem::size_of::<u128>();
mod int;
mod string;
mod tuple;
pub use int::{Int128, UInt128};
pub use string::*;
pub use tuple::*;

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub struct Value<'a>(pub &'a [u8]);

#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ValueId {
    Int = 0x00,
    UInt = 0x01,
    Buffer = 0x02,
    BoolTrue = 0x03,
    BoolFalse = 0x04,
    StandardPrincipal = 0x05,
    ContractPrincipal = 0x06,
    ResponseOk = 0x07,
    ResponseErr = 0x08,
    OptionalNone = 0x09,
    OptionalSome = 0x0a,
    List = 0x0b,
    Tuple = 0x0c,
    StringAscii = 0x0d,
    StringUtf8 = 0x0e,
}

impl TryFrom<u8> for ValueId {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00..=0x0e => unsafe { Ok(core::mem::transmute::<u8, ValueId>(value)) },
            _ => Err(ParserError::parser_unexpected_type),
        }
    }
}

impl ValueId {
    pub fn from_bytes(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, id) = le_u8(bytes)?;
        let value_id = Self::try_from(id)?;

        Ok((rem, value_id))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tuple_value() {
        let encoded = "0c0000000201610000000000000000000000000000000001016303";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::Tuple));
        assert_eq!(bytes.len(), value.0.len());

        let encoded2 = "0c0000000d016100000000000000000000000000000000010162000000000000000000000000000000000101630000000000000000000000000000000001016400000000000000000000000000000000010165000000000000000000000000000000000101660000000000000000000000000000000001016700000000000000000000000000000000010168000000000000000000000000000000000101690000000000000000000000000000000001016a0000000000000000000000000000000001016b00000000000000000000000000000000010171000000000000000000000000000000000101760000000000000000000000000000000001";
        let bytes = hex::decode(encoded2).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::Tuple));
        assert_eq!(bytes.len(), value.0.len());

        // Tuple containing 3 tuples inside
        let encoded3 = "0c0000000401610c00000002016100000000000000000000000000000000010162000000000000000000000000000000000101620c000000020161000000000000000000000000000000000101620301630c000000020161000000000000000000000000000000000101620301760000000000000000000000000000000001";
        let bytes = hex::decode(encoded3).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::Tuple));
        assert_eq!(bytes.len(), value.0.len());
    }

    #[test]
    fn test_list_value() {
        // simple list with 3-ints
        let encoded = "0b00000003000000000000000000000000000000000100000000000000000000000000000000020000000000000000000000000000000003";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::List));
        assert_eq!(bytes.len(), value.0.len());

        let three_nested_list = "0b000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b00000003000000000000000000000000000000000100000000000000000000000000000000020000000000000000000000000000000003";
        let bytes = hex::decode(three_nested_list).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::List));
        assert_eq!(bytes.len(), value.0.len());

        let four_nested_list = "0b000000040b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b00000003000000000000000000000000000000000100000000000000000000000000000000020000000000000000000000000000000003";
        let bytes = hex::decode(four_nested_list).unwrap();
        // should fail, too depth value(4-recursion levels)
        Value::value_len::<2>(&bytes).unwrap_err();
    }

    #[test]
    fn test_optional_value() {
        // simple list with 3-Options
        let encoded =
            "0b000000030a000000000000000000000000000000000f090a000000000000000000000000000000000f";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::List));
        assert_eq!(bytes.len(), value.0.len());

        let three_depth = "0a0a0a0100000000000000000000000000000001";
        let bytes = hex::decode(three_depth).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::OptionalSome));
        assert_eq!(bytes.len(), value.0.len());

        let five_depth = "0a0a0a0a0a0100000000000000000000000000000001";
        let bytes = hex::decode(five_depth).unwrap();
        // should fail, too depth value(4-recursion levels)
        Value::value_len::<3>(&bytes).unwrap_err();
    }

    #[test]
    fn test_buff_value() {
        // simple list with 3-Options
        let encoded = "020000001600deadbeef00080919558081fa240400010204080907";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::Buffer));
        assert_eq!(bytes.len(), value.0.len());
    }

    #[test]
    fn test_string_ascii() {
        // simple list with 3-Options
        let encoded = "0d0000006d31323334353637383930717766706261727374677a786364767a603c3637383930302d6a6c75793b6d6e656f6b682c2e2f6f6b682c2e2f3e3f7b7d7b7d5b5d5b5d313233343561727374677a78636476617172667374676e65696f613b7975657374726569616f697265736864727374677a78636476617172667374676e65696f613b7975657374726569616f697265736864";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::StringAscii));
    }

    #[test]
    fn test_string_utf8() {
        // simple list with 3-Options
        let encoded = "0e0000002d436f6e73696465722074686520656e636f64696e67206f6620746865206575726f207369676e2c20e282ac3a20";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes::<10>(&bytes).unwrap();
        assert!(matches!(value.value_id(), ValueId::StringUtf8));
    }
}

impl<'a> Value<'a> {
    pub fn from_bytes<const MAX_DEPTH: u8>(
        bytes: &'a [u8],
    ) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        c_zemu_log_stack("Value::from_bytes\x00");

        let len = Self::value_len::<MAX_DEPTH>(bytes)?;
        take(len)(bytes).map(|(rem, v)| (rem, Self(v)))
    }

    pub fn value_id(&self) -> ValueId {
        // should not panic as Value was already parsed
        ValueId::try_from(self.0[0]).unwrap()
    }

    // returns the bytes that represent the Value data
    // removing the value_id which is the first byte
    pub fn payload(&self) -> &'a [u8] {
        // wont panic as Value was already parsed
        &self.0[1..]
    }

    // return all bytes this value holds including the value_id
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn tuple(&'a self) -> Option<Tuple<'a>> {
        Tuple::new(self).ok()
    }

    pub fn uint(&'a self) -> Option<u128> {
        UInt128::new(self).map(|v| v.value()).ok()
    }

    pub fn int(&'a self) -> Option<i128> {
        Int128::new(self).map(|v| v.value()).ok()
    }

    pub fn string_ascii(&'a self) -> Option<StringAscii<'a>> {
        StringAscii::new(self).ok()
    }

    pub fn string_utf8(&'a self) -> Option<StringUtf8<'a>> {
        StringUtf8::new(self).ok()
    }

    pub fn value_len<const MAX_DEPTH: u8>(bytes: &'a [u8]) -> Result<usize, nom::Err<ParserError>> {
        if bytes.is_empty() {
            return Err(ParserError::parser_unexpected_buffer_end.into());
        }

        let mut depth = 0;

        Self::value_len_impl::<MAX_DEPTH>(&mut depth, bytes)
    }

    fn value_len_impl<const MAX_DEPTH: u8>(
        depth: &mut u8,
        bytes: &'a [u8],
    ) -> Result<usize, nom::Err<ParserError>> {
        check_canary!();
        if *depth > MAX_DEPTH {
            c_zemu_log_stack("Error recursion limit reached!");
            return Err(ParserError::parser_recursion_limit.into());
        }
        if bytes.is_empty() {
            return Ok(0);
        }

        // get value_id
        let (rem, id) =
            ValueId::from_bytes(bytes).map_err(|_| ParserError::parser_unexpected_value)?;

        let len = match id {
            ValueId::Int | ValueId::UInt => BIG_INT_SIZE,
            ValueId::Buffer => {
                // value_len + 4-bytes
                be_u32(rem).map(|(_, len)| len as usize + 4)?
            }
            ValueId::BoolTrue | ValueId::BoolFalse => 0,
            ValueId::StandardPrincipal => StandardPrincipal::BYTES_LEN,
            ValueId::ContractPrincipal => {
                let (_, contract_bytes) = ContractPrincipal::read_as_bytes(rem)?;
                contract_bytes.len()
            }
            ValueId::OptionalNone => 0,
            ValueId::List => Self::list_len::<MAX_DEPTH>(depth, rem)?,
            ValueId::Tuple => Self::tuple_len::<MAX_DEPTH>(depth, rem)?,
            ValueId::StringAscii | ValueId::StringUtf8 => {
                let (rem, len) = be_u32(rem)?;
                if rem.len() < len as usize {
                    return Err(ParserError::parser_unexpected_buffer_end.into());
                }
                if id == ValueId::StringAscii && !(rem[..len as usize]).is_ascii() {
                    return Err(ParserError::parser_unexpected_type.into());
                }
                len as usize + 4
            }
            // parse the other types that require recursion
            ValueId::ResponseErr | ValueId::ResponseOk | ValueId::OptionalSome => {
                if rem.is_empty() {
                    return Err(nom::Err::Error(ParserError::parser_unexpected_buffer_end));
                }

                // Increase recursion counter
                *depth += 1;
                Self::value_len_impl::<MAX_DEPTH>(depth, rem)?
            }
        };

        // len plus clarity value type
        Ok(len + 1)
    }

    fn tuple_len<const MAX_DEPTH: u8>(
        depth: &mut u8,
        bytes: &'a [u8],
    ) -> Result<usize, nom::Err<ParserError>> {
        // Check iteration counter
        if *depth > MAX_DEPTH {
            c_zemu_log_stack("Error recursion limit reached!");
            return Err(ParserError::parser_recursion_limit.into());
        }

        let (rem, num_pairs) = be_u32(bytes)?;
        let mut len = 0;
        let mut remain: &[u8] = rem;

        for _ in 0..num_pairs {
            let (_, item_id) = ValueId::from_bytes(remain)?;
            if item_id == ValueId::Tuple {
                *depth += 1;
            }

            let (rem, key) = ClarityName::read_as_bytes(remain)?;
            let key_len = key.len();

            let value_len = Self::value_len_impl::<MAX_DEPTH>(depth, rem)?;

            // Read out the bytes that represent the tuple pair being parsed
            // and update the remainder bytes
            let (rem, _) = take(key_len + value_len)(remain)?;
            remain = rem;

            // update our global byte-counter for this Tuple
            len += key_len + value_len;
        }

        // The total bytes for this tuple is 1-byte valueId + 4-byte tuple len + total_len inner
        // pairs, but the value-id byte is added by the caller
        Ok(len + 4)
    }

    fn list_len<const MAX_DEPTH: u8>(
        depth: &mut u8,
        bytes: &'a [u8],
    ) -> Result<usize, nom::Err<ParserError>> {
        // Check for the recursion limit
        if *depth > MAX_DEPTH {
            c_zemu_log_stack("Error recursion limit reached!");
            return Err(ParserError::parser_recursion_limit.into());
        }

        // Read the number of items this list contains
        let (rem, num_items) = be_u32(bytes)?;

        let mut len = 0;
        let mut remain: &[u8] = rem;

        // start parsing each item
        for _ in 0..num_items {
            let (_, item_id) = ValueId::from_bytes(remain)?;

            if item_id == ValueId::List {
                *depth += 1;
            }
            let item_len = Self::value_len_impl::<MAX_DEPTH>(depth, remain)?;

            // update the raw data so, we parse the next tuple pair
            let (rem, _) = take(item_len)(remain)?;
            remain = rem;

            // update our global byte-counter for this Tuple
            len += item_len;
        }

        // The total bytes for this list are 1-byte valueId + 4-byte list_len + total_len inner
        // pairs, although the 1-byte id is added by the caller
        Ok(len + 4)
    }
}
