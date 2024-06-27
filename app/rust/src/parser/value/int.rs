use core::convert::TryFrom;

use nom::number::complete::{be_i128, be_u128};

use crate::parser::error::ParserError;

use super::ValueId;

const INT_WIDTH: usize = 16;

// Represents the inner bytes which conform either a Int128 as defined by SIP005 regarding
// clarity values types.
#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
struct IntBytes<'a>(&'a [u8; INT_WIDTH]);

// Represents a clarity signed integer of 128 bits
#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Int128(i128);

// Represents a clarity unsigned integer of 128 bits
#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct UInt128(u128);

impl Int128 {
    pub(crate) fn new(value: &super::Value) -> Result<Self, ParserError> {
        if !matches!(value.value_id(), ValueId::Int) {
            return Err(ParserError::UnexpectedType.into());
        }

        // omit value_type as we know it is an int
        be_i128(value.payload())
            .map(|(_, v)| Self(v))
            .map_err(|e| e.into())
    }

    pub fn from_bytes(data: &[u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        if data.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }

        if !matches!(ValueId::try_from(data[0])?, ValueId::Int) {
            return Err(ParserError::UnexpectedType.into());
        }

        // check the number is parsed
        let (rem, n) = be_i128(&data[1..])?;
        Ok((rem, Self(n)))
    }

    pub fn value(&self) -> i128 {
        self.0
    }
}

impl UInt128 {
    pub(crate) fn new(value: &super::Value) -> Result<Self, ParserError> {
        if !matches!(value.value_id(), ValueId::UInt) {
            return Err(ParserError::UnexpectedType.into());
        }

        // omit value_type as we know it is an uint
        be_u128(value.payload())
            .map(|(_, v)| Self(v))
            .map_err(|e| e.into())
    }

    pub fn from_bytes(data: &[u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        if data.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }

        if !matches!(ValueId::try_from(data[0])?, ValueId::UInt) {
            return Err(ParserError::UnexpectedType.into());
        }

        // check the number is parsed
        let (rem, n) = be_u128(&data[1..])?;
        Ok((rem, Self(n)))
    }

    pub fn value(&self) -> u128 {
        self.0
    }
}
