use nom::bytes::complete::take;

use super::{c32, ContractName, ParserError, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN};

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct StandardPrincipal<'a>(pub &'a [u8]);

impl<'a> StandardPrincipal<'a> {
    // The required amount of bytes in order to parse this object
    pub const BYTES_LEN: usize = HASH160_LEN + 1;

    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (raw, address) = take(Self::BYTES_LEN)(bytes)?;
        Ok((raw, Self(address)))
    }
}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ContractPrincipal<'a>(StandardPrincipal<'a>, ContractName<'a>);
impl<'a> ContractPrincipal<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, address) = StandardPrincipal::from_bytes(bytes)?;
        let (rem, name) = ContractName::from_bytes(rem)?;
        Ok((rem, Self(address, name)))
    }

    pub fn read_as_bytes(bytes: &'a [u8]) -> Result<(&[u8], &[u8]), nom::Err<ParserError>> {
        let (rem, _) = Self::from_bytes(bytes)?;
        let len = bytes.len() - rem.len();
        let (rem, self_bytes) = take(len)(bytes)?;
        Ok((rem, self_bytes))
    }
}

#[repr(C)]
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct PrincipalData<'a> {
    pub data: (StandardPrincipal<'a>, Option<ContractName<'a>>),
}

impl<'a> PrincipalData<'a> {
    #[inline(never)]
    pub fn standard_from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, principal) = StandardPrincipal::from_bytes(bytes)?;
        Ok((
            raw,
            Self {
                data: (principal, None),
            },
        ))
    }

    #[inline(never)]
    pub fn contract_principal_from_bytes(
        bytes: &'a [u8],
    ) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, address) = StandardPrincipal::from_bytes(bytes)?;
        let (raw2, name) = ContractName::from_bytes(raw)?;
        Ok((
            raw2,
            Self {
                data: (address, Some(name)),
            },
        ))
    }

    pub fn version(&self) -> u8 {
        (self.data.0).0[0]
    }

    pub fn raw_address(&self) -> &[u8] {
        &(self.data.0).0[1..]
    }

    #[inline(never)]
    pub fn encoded_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let version = self.version();
        let address = self.raw_address();
        c32::c32_address(version, address)
    }
}
