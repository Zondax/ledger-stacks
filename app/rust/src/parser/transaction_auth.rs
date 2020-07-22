use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::check_canary;
use crate::parser::parser_common::ParserError;
use crate::parser::spending_condition::TransactionSpendingCondition;

#[repr(C)]
#[derive(Debug)]
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
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let auth_type = le_u8(bytes)?;
        let auth = match auth_type.1 {
            0x04 => Self::standard_from_bytes(auth_type.0)?,
            0x05 => Self::sponsored_from_bytes(auth_type.0)?,
            _ => return Err(nom::Err::Error(ParserError::parser_invalid_auth_type)),
        };
        Ok(auth)
    }

    #[inline(never)]
    fn standard_from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        check_canary!();
        Ok((standard.0, Self::Standard(standard.1)))
    }

    #[inline(never)]
    fn sponsored_from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        let sponsored = TransactionSpendingCondition::from_bytes(standard.0)?;
        check_canary!();
        Ok((sponsored.0, Self::Sponsored(standard.1, sponsored.1)))
    }

    #[inline(never)]
    pub fn is_standard_auth(&self) -> bool {
        match *self {
            Self::Standard(_) => true,
            _ => false,
        }
    }

    pub fn origin(&self) -> &TransactionSpendingCondition {
        match *self {
            Self::Standard(ref origin) | Self::Sponsored(ref origin, _) => origin,
        }
    }

    pub fn sponsor(&self) -> Option<&TransactionSpendingCondition> {
        match *self {
            Self::Sponsored(_, ref sponsor) => Some(sponsor),
            _ => None,
        }
    }

    pub fn num_spending_conditions(&self) -> u8 {
        if self.is_standard_auth() {
            1
        } else {
            2
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::println;
    use std::vec::Vec;
}
