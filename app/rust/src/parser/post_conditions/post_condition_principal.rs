use core::convert::TryFrom;

use arrayvec::ArrayVec;
use nom::{bytes::complete::take, number::complete::le_u8};

use crate::parser::{
    ContractName, ParserError, StacksAddress, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN,
};

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum PostConditionPrincipalId {
    Origin = 0x01,
    Standard = 0x02,
    Contract = 0x03,
}

impl TryFrom<u8> for PostConditionPrincipalId {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let id = match value {
            1 => Self::Origin,
            2 => Self::Standard,
            3 => Self::Contract,
            _ => return Err(ParserError::UnexpectedValue),
        };
        Ok(id)
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum PostConditionPrincipal<'a> {
    Origin,
    Standard(StacksAddress<'a>),
    Contract(StacksAddress<'a>, ContractName<'a>),
}

impl<'a> PostConditionPrincipal<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let principal_id = PostConditionPrincipalId::try_from(id.1)?;
        match principal_id {
            PostConditionPrincipalId::Origin => Ok((id.0, PostConditionPrincipal::Origin)),
            PostConditionPrincipalId::Standard => {
                let addrs = StacksAddress::from_bytes(id.0)?;
                Ok((addrs.0, PostConditionPrincipal::Standard(addrs.1)))
            }
            PostConditionPrincipalId::Contract => {
                let addrs = StacksAddress::from_bytes(id.0)?;
                let contract_name = ContractName::from_bytes(addrs.0)?;
                Ok((
                    contract_name.0,
                    PostConditionPrincipal::Contract(addrs.1, contract_name.1),
                ))
            }
        }
    }

    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let (rem, id) = le_u8(bytes)?;
        let principal_id = PostConditionPrincipalId::try_from(id)?;
        match principal_id {
            PostConditionPrincipalId::Origin => Ok((rem, Default::default())),
            PostConditionPrincipalId::Standard => {
                // we take 20-byte key hash + 1-byte hash_mode + 1-byte principal_id
                let (raw, addr) = take(HASH160_LEN + 2usize)(bytes)?;
                Ok((raw, addr))
            }
            PostConditionPrincipalId::Contract => {
                let (rem, _) = StacksAddress::from_bytes(rem)?;
                let (_, name) = ContractName::from_bytes(rem)?;
                // we take 20-byte key hash + 1-byte hash_mode +
                // contract_name len + 1-byte len + 1-byte principal_id
                let total_len = HASH160_LEN + name.len() + 3;
                let (rem, contract_bytes) = take(total_len)(bytes)?;
                Ok((rem, contract_bytes))
            }
        }
    }

    pub fn is_origin(&self) -> bool {
        matches!(self, Self::Origin)
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, Self::Standard(..))
    }

    pub fn is_contract(&self) -> bool {
        matches!(self, Self::Contract(..))
    }

    pub fn origin_address(
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let mut output: ArrayVec<[_; C32_ENCODED_ADDRS_LENGTH]> = ArrayVec::new();
        output.try_extend_from_slice(b"Origin".as_ref()).unwrap();
        Ok(output)
    }

    pub fn get_principal_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        match self {
            Self::Origin => Self::origin_address(),
            Self::Standard(ref address) | Self::Contract(ref address, _) => {
                address.encoded_address()
            }
        }
    }

    pub fn get_contract_name(&'a self) -> Option<&'a [u8]> {
        match self {
            Self::Contract(_, name) => Some(name.name()),
            _ => None,
        }
    }
}
