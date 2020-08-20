use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::check_canary;
use crate::parser::parser_common::{ParserError, SignerId};
use crate::parser::spending_condition::TransactionSpendingCondition;

// The sponsor sentinel length that includes:
// 21-byte pub_key hash
// 16-byte fee and nonce
// 66-byte signature and signature encoding
const SPONSOR_SENTINEL_LEN: usize = 21 + 16 + 66;

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

    pub fn origin_fee(&self) -> u64 {
        match self {
            Self::Standard(ref origin) => origin.fee(),
            Self::Sponsored(ref origin, _) => origin.fee(),
        }
    }

    pub fn origin_nonce(&self) -> u64 {
        match self {
            Self::Standard(ref origin) => origin.nonce(),
            Self::Sponsored(ref origin, _) => origin.nonce(),
        }
    }

    pub fn sponsor_fee(&self) -> Option<u64> {
        match self {
            Self::Standard(_) => None,
            Self::Sponsored(_, ref sponsor) => Some(sponsor.fee()),
        }
    }

    pub fn sponsor_nonce(&self) -> Option<u64> {
        match self {
            Self::Standard(_) => None,
            Self::Sponsored(_, ref sponsor) => Some(sponsor.nonce()),
        }
    }

    pub fn check_signer(&self, signer_pk: &[u8]) -> SignerId {
        match self {
            Self::Standard(ref origin) => {
                if signer_pk == origin.signer_pub_key_hash() {
                    return SignerId::Origin;
                }
            }
            Self::Sponsored(ref origin, ref sponsor) => {
                if signer_pk == origin.signer_pub_key_hash() {
                    return SignerId::Origin;
                } else if signer_pk == sponsor.signer_pub_key_hash() {
                    return SignerId::Sponsor;
                }
            }
        }
        SignerId::Invalid
    }

    pub fn initial_sighash_auth(&self, buf: &mut [u8]) -> Result<usize, ()> {
        match self {
            Self::Standard(ref origin) => origin.init_sighash(buf),
            Self::Sponsored(ref origin, _) => {
                let len = origin.init_sighash(buf)?;
                TransactionAuth::write_sponsor_sentinel(&mut buf[len..])
            }
        }
    }

    pub fn write_sponsor_sentinel(buf: &mut [u8]) -> Result<usize, ()> {
        if buf.len() < SPONSOR_SENTINEL_LEN {
            return Err(());
        }
        buf.iter_mut()
            .take(SPONSOR_SENTINEL_LEN)
            .for_each(|v| *v = 0);

        Ok(SPONSOR_SENTINEL_LEN)
    }
}
