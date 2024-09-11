use nom::bytes::complete::take;

use super::{c32, ApduPanic, ContractName, ParserError, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN};

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

    pub fn version(&self) -> u8 {
        // safe to unwrap as this was checked when parsing
        *self.0.first().apdu_unwrap()
    }

    pub fn raw_address(&self) -> &'a [u8] {
        // safe to unwrap as slice contains enough data
        // checked at parsing stage
        self.0.get(1..).apdu_unwrap()
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

    pub fn version(&self) -> u8 {
        // safe to unwrap as this was checked when parsing
        self.0.version()
    }

    pub fn raw_address(&self) -> &'a [u8] {
        // safe to unwrap as slice contains enough data
        // checked at parsing stage
        self.0.raw_address()
    }

    pub fn contract_name(&self) -> ContractName<'a> {
        self.1
    }
}

#[repr(C)]
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum PrincipalData<'a> {
    Standard(StandardPrincipal<'a>),
    Contract(ContractPrincipal<'a>),
}

impl<'a> PrincipalData<'a> {
    #[inline(never)]
    pub fn standard_from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        StandardPrincipal::from_bytes(bytes).map(|(r, p)| (r, Self::Standard(p)))
    }

    #[inline(never)]
    pub fn contract_principal_from_bytes(
        bytes: &'a [u8],
    ) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        ContractPrincipal::from_bytes(bytes).map(|(r, p)| (r, Self::Contract(p)))
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::Standard(ref p) => p.version(),
            Self::Contract(ref p) => p.version(),
        }
    }

    // returns principal address without the address version byte
    pub fn raw_address(&self) -> &[u8] {
        match self {
            Self::Standard(ref p) => p.raw_address(),
            Self::Contract(ref p) => p.raw_address(),
        }
    }

    #[inline(never)]
    pub fn encoded_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let version = self.version();
        let address = self.raw_address();
        c32::c32_address(version, address)
    }

    pub fn contract_name(&self) -> Option<ContractName<'a>> {
        match self {
            Self::Standard(..) => None,
            Self::Contract(p) => Some(p.contract_name()),
        }
    }
}
