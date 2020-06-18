use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::parser::parser_common::ParserError;
use crate::parser::spending_condition::TransactionSpendingCondition;

const MAX_ADDRESS_BUFFER_LEN: usize = 40;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Address {
    addr: [u8; MAX_ADDRESS_BUFFER_LEN],
    pub len: usize,
}

#[repr(C)]
/// A Transaction's Authorization structure
///
/// this structure contains the address of the origin account,
/// signature(s) and signature threshold for the origin account
pub enum TransactionAuth<'a> {
    // 0x04
    Standard(TransactionSpendingCondition<'a>),
    // 0x05 the second account pays on behalf of the first account
    Sponsored(
        TransactionSpendingCondition<'a>,
        TransactionSpendingCondition<'a>,
    ),
}

impl<'a> TransactionAuth<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let auth_type = le_u8(bytes)?;
        let auth = match auth_type.1 {
            0x04 => Self::standard_from_bytes(auth_type.0)?,
            0x05 => Self::sponsored_from_bytes(auth_type.0)?,
            _ => return Err(nom::Err::Error(ParserError::parser_invalid_auth_type)),
        };
        Ok(auth)
    }

    fn standard_from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        Ok((standard.0, Self::Standard(standard.1)))
    }

    fn sponsored_from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        let sponsored = TransactionSpendingCondition::from_bytes(standard.0)?;
        Ok((sponsored.0, Self::Sponsored(standard.1, sponsored.1)))
    }

    pub fn is_standard_auth(&self) -> bool {
        match *self {
            Self::Standard(_) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::println;
    use std::vec::Vec;
}
