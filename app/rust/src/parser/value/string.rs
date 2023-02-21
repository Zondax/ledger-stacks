use super::{ParserError, Value, ValueId};
use nom::{bytes::complete::take, number::complete::be_u32};

// Represent a clarity value string
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
struct String<'a>(&'a [u8]);

// Represent a clarity value string
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct StringAscii<'a>(String<'a>);

// Represent a clarity value string
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct StringUtf8<'a>(String<'a>);

impl<'a> String<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&'a [u8], String<'a>), nom::Err<ParserError>> {
        let (rem, len) = be_u32(bytes)?;
        let (rem, string) = take(len)(rem)?;
        Ok((rem, Self(string)))
    }

    #[inline(never)]
    pub fn from_bytes_ascii(
        bytes: &'a [u8],
    ) -> Result<(&'a [u8], String<'a>), nom::Err<ParserError>> {
        let (rem, s) = Self::from_bytes(bytes)?;

        if !s.0.is_ascii() {
            return Err(ParserError::parser_unexpected_value.into());
        }

        Ok((rem, s))
    }

    pub fn is_ascii(&self) -> bool {
        self.0.is_ascii()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn content(&self) -> &[u8] {
        self.0
    }
}

impl<'a> StringAscii<'a> {
    pub(crate) fn new(value: &Value<'a>) -> Result<StringAscii<'a>, ParserError> {
        if !matches!(value.value_id(), ValueId::StringAscii) {
            return Err(ParserError::parser_unexpected_type.into());
        }

        String::from_bytes_ascii(value.payload())
            .map(|(_, s)| Self(s))
            .map_err(|e| e.into())
    }

    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], StringAscii<'a>), nom::Err<ParserError>> {
        let (rem, id) = ValueId::from_bytes(bytes)?;

        if !matches!(id, ValueId::StringAscii) {
            return Err(ParserError::parser_unexpected_type.into());
        }

        let (rem, string) = String::from_bytes_ascii(rem)?;

        Ok((rem, Self(string)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn content(&self) -> &[u8] {
        self.0.content()
    }
}

impl<'a> StringUtf8<'a> {
    pub(crate) fn new(value: &Value<'a>) -> Result<Self, ParserError> {
        if !matches!(value.value_id(), ValueId::StringUtf8) {
            return Err(ParserError::parser_unexpected_type.into());
        }

        let (_, string) = String::from_bytes(value.payload())?;
        Ok(Self(string))
    }

    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, id) = ValueId::from_bytes(bytes)?;

        if !matches!(id, ValueId::StringUtf8) {
            return Err(ParserError::parser_unexpected_type.into());
        }

        let (rem, string) = String::from_bytes(rem)?;

        Ok((rem, Self(string)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn content(&self) -> &[u8] {
        self.0.content()
    }
}
