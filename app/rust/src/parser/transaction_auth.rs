use nom::number::complete::le_u8;

use crate::check_canary;
use crate::parser::{
    error::ParserError,
    parser_common::{HashMode, SignerId},
    spending_condition::{
        SpendingConditionSigner, TransactionAuthField, TransactionSpendingCondition,
    },
};

// The sponsor sentinel length that includes:
// 21-byte pub_key hash
// 16-byte fee and nonce
// 66-byte signature and signature encoding
const SPONSOR_SENTINEL_LEN: usize = 21 + 16 + 66;

/// A Transaction's Authorization structure
///
/// this structure contains the address of the origin account,
/// signature(s) and signature threshold for the origin account
#[repr(C)]
#[derive(PartialEq, Clone)]
#[cfg_attr(test, derive(Debug))]
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
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let auth_type = le_u8(bytes)?;
        let auth = match auth_type.1 {
            0x04 => Self::standard_from_bytes(auth_type.0)?,
            0x05 => Self::sponsored_from_bytes(auth_type.0)?,
            _ => return Err(nom::Err::Error(ParserError::InvalidAuthType)),
        };
        Ok(auth)
    }

    #[inline(never)]
    fn standard_from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        check_canary!();
        Ok((standard.0, Self::Standard(standard.1)))
    }

    #[inline(never)]
    fn sponsored_from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let standard = TransactionSpendingCondition::from_bytes(bytes)?;
        let sponsored = TransactionSpendingCondition::from_bytes(standard.0)?;
        check_canary!();
        Ok((sponsored.0, Self::Sponsored(standard.1, sponsored.1)))
    }

    #[inline(never)]
    pub fn is_standard_auth(&self) -> bool {
        matches!(*self, Self::Standard(_))
    }

    // check just for origin, meaning we support standard transaction only
    pub fn is_multisig(&self) -> bool {
        match self {
            Self::Standard(origin) => origin.is_multisig(),
            Self::Sponsored(origin, _) => origin.is_multisig(),
        }
    }

    // check just for origin, meaning we support standard transaction only
    pub fn hash_mode(&self) -> Result<HashMode, ParserError> {
        match self {
            Self::Standard(origin) => origin.hash_mode(),
            Self::Sponsored(origin, _) => origin.hash_mode(),
        }
    }

    // check just for origin, meaning we support standard transaction only
    pub fn num_auth_fields(&self) -> Option<u32> {
        match self {
            Self::Standard(origin) => origin.num_auth_fields(),
            Self::Sponsored(origin, _) => origin.num_auth_fields(),
        }
    }

    // check just for origin, meaning we support standard transaction only
    pub fn get_auth_field(&self, index: u32) -> Option<Result<TransactionAuthField<'_>, ParserError>> {
        match self {
            Self::Standard(origin) => origin.get_auth_field(index),
            Self::Sponsored(origin, _) => origin.get_auth_field(index),
        }
    }

    #[inline(always)]
    pub fn origin(&self) -> &SpendingConditionSigner<'_> {
        match self {
            Self::Standard(ref origin) | Self::Sponsored(ref origin, _) => &origin.signer,
        }
    }

    #[inline(always)]
    pub fn sponsor(&self) -> Option<&SpendingConditionSigner<'_>> {
        match self {
            Self::Sponsored(_, ref sponsor) => Some(&sponsor.signer),
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
                // Multisig support just for non sponsored transactions
                if signer_pk == origin.signer_pub_key_hash() || origin.is_multisig() {
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

    pub fn initial_sighash_auth(&self, buf: &mut [u8]) -> Result<usize, ParserError> {
        match self {
            Self::Standard(ref origin) => origin.init_sighash(buf),
            Self::Sponsored(ref origin, _) => {
                let len = origin.init_sighash(buf)?;
                let sentinel_len = TransactionAuth::write_sponsor_sentinel(&mut buf[len..])?;
                Ok(len + sentinel_len)
            }
        }
    }

    pub fn write_sponsor_sentinel(buf: &mut [u8]) -> Result<usize, ParserError> {
        if buf.len() < SPONSOR_SENTINEL_LEN {
            return Err(ParserError::NoData);
        }
        buf.iter_mut()
            .take(SPONSOR_SENTINEL_LEN)
            .for_each(|v| *v = 0);

        Ok(SPONSOR_SENTINEL_LEN)
    }
}
