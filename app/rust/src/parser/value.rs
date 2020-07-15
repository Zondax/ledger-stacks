use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u32, le_u8},
};

use crate::parser::parser_common::{ContractName, ContractPrincipal, ParserError, StacksAddress};

// Big ints size in bytes
pub const BIG_INT_SIZE: usize = 16;

// Max buffer length in bytes
pub const MAX_BUFFER_LEN: usize = 256;
// The max number of tuple elements
pub const MAX_TUPLE_ELEMENTS: usize = 4;

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum Value<'a> {
    Int(&'a [u8]),
    UInt(&'a [u8]),
    Bool(bool),
    Buffer(&'a [u8]),
    List(&'a [u8]),
    StandardPrincipal(StacksAddress<'a>),
    ContractPrincipal(&'a [u8]),
    Tuple(&'a [u8]),
    Optional(&'a [u8]),
    Response(&'a [u8]),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ValueId {
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
        let value_id = ValueId::from_bytes(bytes)?;
        let res = match value_id.1 {
            ValueId::Int => {
                let int = take(BIG_INT_SIZE)(value_id.0)?;
                (int.0, Self::Int(int.1))
            }
            ValueId::UInt => {
                let int = take(BIG_INT_SIZE)(value_id.0)?;
                (int.0, Self::UInt(int.1))
            }
            ValueId::Buffer => {
                let len = be_u32(value_id.0)?;
                let buff = take(len.1)(len.0)?;
                (buff.0, Self::Buffer(buff.1))
            }
            ValueId::BoolTrue => (value_id.0, Self::Bool(true)),
            ValueId::BoolFalse => (value_id.0, Self::Bool(false)),
            ValueId::StandardPrincipal => {
                let address = StacksAddress::from_bytes(value_id.0)?;
                (address.0, Self::StandardPrincipal(address.1))
            }
            ValueId::ContractPrincipal => {
                let contract = ContractPrincipal::read_as_bytes(value_id.0)?;
                (contract.0, Self::ContractPrincipal(contract.1))
            }
            ValueId::Tuple => {
                let len = be_u32(value_id.0)?;
                let tuple = take(len.1)(len.0)?;
                (tuple.0, Self::Tuple(value_id.0))
            }
            ValueId::List => {
                let len = be_u32(value_id.0)?;
                let list = take(len.1)(value_id.0)?;
                (list.0, Self::List(list.1))
            }
            ValueId::ResponseOk | ValueId::ResponseErr => (value_id.0, Self::Response(value_id.0)),
            ValueId::OptionalSome | ValueId::OptionalNone => {
                (value_id.0, Self::Optional(value_id.0))
            }
        };
        Ok(res)
    }
}
