use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u32, le_u8},
};

use crate::parser::parser_common::{
    ClarityName, ContractName, ContractPrincipal, ParserError, StacksAddress, HASH160_LEN,
};
use arrayvec::ArrayVec;

// Big ints size in bytes
pub const BIG_INT_SIZE: usize = 16;

// Max buffer length in bytes
pub const MAX_BUFFER_LEN: usize = 256;
// The max number of tuple elements
pub const MAX_TUPLE_ELEMENTS: usize = 4;

pub const DEPTH_LIMIT: u8 = 3;

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
}

impl ValueId {
    pub fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let value_id = Self::from_u8(id.1)?;
        Ok((id.0, value_id))
    }

    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            0x00..=0x0c => unsafe { Ok(core::mem::transmute::<u8, ValueId>(v)) },
            _ => Err(ParserError::parser_invalid_argument_id),
        }
    }
}

impl<'a> Value<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = Self::value_len(bytes)?;
        let (leftover, inner) = take(len)(bytes)?;
        Ok((leftover, Self(inner)))
    }

    pub fn value_id(&self) -> Result<ValueId, ParserError> {
        let id = ValueId::from_bytes(self.0).map_err(|_| ParserError::parser_unexpected_value)?;
        Ok(id.1)
    }

    pub fn payload(&self) -> Result<&'a [u8], ParserError> {
        if !self.0.is_empty() {
            Ok(&self.0[1..])
        } else {
            Err(ParserError::parser_unexpected_buffer_end)
        }
    }

    pub fn value_len(bytes: &'a [u8]) -> Result<usize, ParserError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut depth = 0;

        let len = Self::simple_value_len(&mut depth, bytes)
            .map(|res| res.1)
            .map_err(|_| ParserError::parser_value_out_of_range)?;
        Ok(len)
    }

    fn simple_value_len(depth: &mut u8, bytes: &'a [u8]) -> nom::IResult<(), usize, ParserError> {
        if *depth > DEPTH_LIMIT {
            return Err(nom::Err::Error(ParserError::parser_value_out_of_range));
        }
        if bytes.is_empty() {
            return Ok(((), 0));
        }

        let (raw, id) =
            ValueId::from_bytes(bytes).map_err(|_| ParserError::parser_unexpected_value)?;
        let len = match id {
            ValueId::Int | ValueId::UInt => BIG_INT_SIZE,
            ValueId::Buffer => {
                let len = be_u32::<'a, ParserError>(raw)
                    .map_err(|_| ParserError::parser_unexpected_value)?;
                // value_len + 4-bytes
                len.1 as usize + 4
            }
            ValueId::BoolTrue | ValueId::BoolFalse => 0,
            ValueId::StandardPrincipal => HASH160_LEN as usize + 1,
            ValueId::ContractPrincipal => {
                let contract = ContractPrincipal::read_as_bytes(raw)
                    .map_err(|_| ParserError::parser_unexpected_value)?;
                contract.0.len()
            }
            ValueId::OptionalNone => 0,
            ValueId::List => Self::list_len(depth, raw).map(|res| res.1)?,
            ValueId::Tuple => Self::tuple_len(depth, raw).map(|res| res.1)?,
            x => {
                if raw.is_empty() {
                    return Err(nom::Err::Error(ParserError::parser_unexpected_buffer_end));
                }
                if x as u8 == raw[0] || raw[0] == ValueId::OptionalNone as u8 {
                    *depth += 1;
                }
                Self::simple_value_len(depth, raw).map(|res| res.1)?
            }
        };
        Ok(((), len + 1))
    }

    fn tuple_len(depth: &mut u8, bytes: &'a [u8]) -> nom::IResult<(), usize, ParserError> {
        if *depth > DEPTH_LIMIT {
            return Err(nom::Err::Error(ParserError::parser_value_out_of_range));
        }
        if bytes.len() <= 1 {
            return Ok(((), 0));
        }
        let (left, num_pairs) = be_u32::<'_, ParserError>(bytes)?;
        let mut len = 0;
        let mut raw: &[u8] = left;
        for _ in 0..num_pairs {
            let (inner, clarity) = ClarityName::from_bytes(raw)?;
            // 1-byte length prefix + name_length
            let mut item_len = 1 + clarity.0.len();

            let (_, item_id) = ValueId::from_bytes(inner)?;
            if item_id == ValueId::Tuple {
                *depth += 1;
            }
            item_len += Self::simple_value_len(depth, inner).map(|res| res.1)?;
            // update the raw data so, we parse the next tuple pair
            let (leftover, _) = take(item_len)(raw)?;
            raw = leftover;

            // update our global byte-counter for this Tuple
            len += item_len;
        }

        // The total bytes for this tuple is 1-byte valueId + 4-byte tuple len + total_len inner
        // pairs
        let len = 4 + len;
        Ok(((), len))
    }

    fn list_len(depth: &mut u8, bytes: &'a [u8]) -> nom::IResult<(), usize, ParserError> {
        if *depth > DEPTH_LIMIT {
            return Err(nom::Err::Error(ParserError::parser_value_out_of_range));
        }
        if bytes.is_empty() {
            return Ok(((), 0));
        }

        let (rem, num_items) = be_u32::<'_, ParserError>(bytes)?;
        let mut len = 0;
        let mut raw: &[u8] = rem;
        for _ in 0..num_items {
            let (_, item_id) = ValueId::from_bytes(raw)?;
            if item_id == ValueId::List {
                *depth += 1;
            }
            let item_len = Self::simple_value_len(depth, raw).map(|res| res.1)?;
            // update the raw data so, we parse the next tuple pair
            let (leftover, _) = take(item_len)(raw)?;
            raw = leftover;

            // update our global byte-counter for this Tuple
            len += item_len;
        }

        // The total bytes for this list are 1-byte valueId + 4-byte list_len + total_len inner
        // pairs
        let len = 4 + len;
        Ok(((), len))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tuple_value() {
        let encoded = "0c0000000201610000000000000000000000000000000001016303";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        let encoded2 = "0c0000000d016100000000000000000000000000000000010162000000000000000000000000000000000101630000000000000000000000000000000001016400000000000000000000000000000000010165000000000000000000000000000000000101660000000000000000000000000000000001016700000000000000000000000000000000010168000000000000000000000000000000000101690000000000000000000000000000000001016a0000000000000000000000000000000001016b00000000000000000000000000000000010171000000000000000000000000000000000101760000000000000000000000000000000001";
        let bytes = hex::decode(encoded2).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        // Tuple containing 3 tuples inside
        let encoded3 = "0c0000000401610c00000002016100000000000000000000000000000000010162000000000000000000000000000000000101620c000000020161000000000000000000000000000000000101620301630c000000020161000000000000000000000000000000000101620301760000000000000000000000000000000001";
        let bytes = hex::decode(encoded3).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        // this should fail because there are more than DEPTH_LIMIT nested tuples
        let encoded4 = "0c0000000501610c00000002016100000000000000000000000000000000010162000000000000000000000000000000000101620c000000020161000000000000000000000000000000000101620301630c000000020161000000000000000000000000000000000101620301760000000000000000000000000000000001017a0c0000000201610000000000000000000000000000000001016303";
        let bytes = hex::decode(encoded4).unwrap();
        Value::value_len(&bytes).unwrap_err();
    }

    #[test]
    fn test_list_value() {
        // simple list with 3-ints
        let encoded = "0b00000003000000000000000000000000000000000100000000000000000000000000000000020000000000000000000000000000000003";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        let three_nested_list = "0b000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b00000003000000000000000000000000000000000100000000000000000000000000000000020000000000000000000000000000000003";
        let bytes = hex::decode(three_nested_list).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        // should fail, too depth value(4-recursion levels)
        let four_nested_list = "0b000000040b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b000000030000000000000000000000000000000001000000000000000000000000000000000200000000000000000000000000000000030b00000003000000000000000000000000000000000100000000000000000000000000000000020000000000000000000000000000000003";
        let bytes = hex::decode(four_nested_list).unwrap();
        Value::value_len(&bytes).unwrap_err();
    }

    #[test]
    fn test_optional_value() {
        // simple list with 3-Options
        let encoded =
            "0b000000030a000000000000000000000000000000000f090a000000000000000000000000000000000f";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        let three_depth = "0a0a0a0100000000000000000000000000000001";
        let bytes = hex::decode(three_depth).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());

        let five_depth = "0a0a0a0a0a0100000000000000000000000000000001";
        let bytes = hex::decode(five_depth).unwrap();
        Value::value_len(&bytes).unwrap_err();
    }

    #[test]
    fn test_buff_value() {
        // simple list with 3-Options
        let encoded = "020000001600deadbeef00080919558081fa240400010204080907";
        let bytes = hex::decode(encoded).unwrap();
        let (_, value) = Value::from_bytes(&bytes).unwrap();
        assert_eq!(bytes.len(), value.0.len());
    }
}
