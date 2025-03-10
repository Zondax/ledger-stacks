#![allow(clippy::upper_case_acronyms)]
use core::convert::TryFrom;

use nom::{bytes::complete::take, number::complete::le_u8};

use crate::parser::{c32, error::ParserError};

// The max len for asset, contract and clarity names
pub const MAX_STRING_LEN: u8 = 128;
pub const HASH160_LEN: usize = 20;
pub const STACKS_ADDR_LEN: usize = HASH160_LEN + 1;

// The conversion constant between microSTX to STX
pub const STX_DECIMALS: u8 = 6;

pub const C32_ENCODED_ADDRS_LENGTH: usize = 48;

pub const SIGNATURE_LEN: usize = 65;
pub const PUBKEY_LEN: usize = 33;
pub const MEMO_LEN: usize = 34;
pub const AMOUNT_LEN: usize = 8;

// A recursion limit use to control ram usage when parsing
// contract-call arguments that comes in a transaction
pub const TX_DEPTH_LIMIT: u8 = 8;

// Use to limit recursion when parsing nested clarity values that comes as part of a structured
// message. the limit is higher than the one use when parsing contract-args in transactions
// as the ram usage there is higher.
pub const MAX_DEPTH: u8 = 20;

/// Stacks transaction versions
#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

impl TryFrom<u8> for TransactionVersion {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Mainnet),
            0x80 => Ok(Self::Testnet),
            _ => Err(ParserError::UnexpectedValue),
        }
    }
}

impl TransactionVersion {
    #[inline(never)]
    pub fn from_bytes(bytes: &[u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, version) = le_u8(bytes)?;
        let tx_version = Self::try_from(version)?;
        Ok((rem, tx_version))
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum AssetInfoId {
    STX = 0,
    FungibleAsset = 1,
    NonfungibleAsset = 2,
}

impl TryFrom<u8> for AssetInfoId {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let s = match value {
            0 => AssetInfoId::STX,
            1 => AssetInfoId::FungibleAsset,
            2 => AssetInfoId::NonfungibleAsset,
            _ => return Err(ParserError::UnexpectedValue),
        };
        Ok(s)
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct AssetInfo<'a> {
    pub address: StacksAddress<'a>,
    pub contract_name: ContractName<'a>,
    pub asset_name: ClarityName<'a>,
}

impl<'a> AssetInfo<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let address = StacksAddress::from_bytes(bytes)?;
        let (raw, contract_name) = ContractName::from_bytes(address.0)?;
        let asset_name = ClarityName::from_bytes(raw)?;
        Ok((
            asset_name.0,
            Self {
                address: address.1,
                contract_name,
                asset_name: asset_name.1,
            },
        ))
    }

    #[inline(never)]
    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let (raw, _) = StacksAddress::from_bytes(bytes)?;
        let (raw1, _) = ContractName::from_bytes(raw)?;
        let (raw2, _) = ClarityName::from_bytes(raw1)?;
        let len = bytes.len() - raw2.len();
        let (left, inner) = take(len)(bytes)?;
        Ok((left, inner))
    }

    pub fn asset_name(&self) -> &[u8] {
        self.asset_name.0
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
// Flag used to know if the signer is valid and
// who is
pub enum SignerId {
    Origin,
    Sponsor,
    Invalid,
}

// tag address hash modes as "singlesig" or "multisig" so we can't accidentally construct an
// invalid spending condition
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum HashMode {
    P2PKH = 0x00,
    P2SH = 0x01,
    P2WPKH = 0x02,
    P2WSH = 0x03,
    P2SHNS = 0x05,  // Non-sequential multisig
    P2WSHNS = 0x07, // Non-sequential multisig
}

impl TryFrom<u8> for HashMode {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let mode = match value {
            x if x == HashMode::P2PKH as u8 => HashMode::P2PKH,
            x if x == HashMode::P2WPKH as u8 => HashMode::P2WPKH,
            x if x == HashMode::P2SH as u8 => HashMode::P2SH,
            x if x == HashMode::P2WSH as u8 => HashMode::P2WSH,
            x if x == HashMode::P2SHNS as u8 => HashMode::P2SHNS,
            x if x == HashMode::P2WSHNS as u8 => HashMode::P2WSHNS,
            _ => return Err(ParserError::InvalidHashMode),
        };
        Ok(mode)
    }
}

impl HashMode {
    pub fn to_version_mainnet(self) -> u8 {
        match self {
            HashMode::P2PKH => c32::C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            _ => c32::C32_ADDRESS_VERSION_MAINNET_MULTISIG,
        }
    }

    pub fn to_version_testnet(self) -> u8 {
        match self {
            HashMode::P2PKH => c32::C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            _ => c32::C32_ADDRESS_VERSION_TESTNET_MULTISIG,
        }
    }
}

// contract name with valid charactes being
// ^[a-zA-Z]([a-zA-Z0-9]|[-_])*$
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct ContractName<'a>(ClarityName<'a>);

impl<'a> ContractName<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, name) = ClarityName::from_bytes(bytes)?;

        // we are using the ClarityName inner type to wrap-up the parsing which is the same for
        // Contract names, but the docs do not say nothing about what is a valid clarity name either
        // ascii or utf8 values, lets check it here.
        if !name.0.is_ascii() {
            return Err(ParserError::InvalidContractName.into());
        }

        Ok((rem, Self(name)))
    }

    pub fn name(&'a self) -> &'a [u8] {
        self.0.name()
    }

    pub fn len(&self) -> usize {
        self.name().len()
    }

    pub fn is_empty(&self) -> bool {
        self.name().is_empty()
    }
}

// A clarity value used in tuples
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct ClarityName<'a>(pub &'a [u8]);

impl<'a> ClarityName<'a> {
    pub const MAX_LEN: u8 = 128;

    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        let (rem, name) = Self::read_as_bytes(bytes)?;
        // Omit the first byte as it is the encoded length
        Ok((rem, Self(&name[1..])))
    }

    #[inline(never)]
    pub fn read_as_bytes(bytes: &'a [u8]) -> Result<(&[u8], &[u8]), nom::Err<ParserError>> {
        let (_, len) = le_u8(bytes)?;

        if len >= Self::MAX_LEN {
            return Err(ParserError::ValueOutOfRange.into());
        }

        // include the 1-byte len
        take(len + 1)(bytes)
    }

    pub fn name(&'a self) -> &'a [u8] {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
// we take HASH160_LEN + 1-byte hash mode
pub struct StacksAddress<'a>(pub &'a [u8; STACKS_ADDR_LEN]);

impl<'a> StacksAddress<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, _) = take(STACKS_ADDR_LEN)(bytes)?;
        let address = arrayref::array_ref!(bytes, 0, STACKS_ADDR_LEN);
        Ok((raw, Self(address)))
    }

    pub fn encoded_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        c32::c32_address(self.0[0], &self.0[1..])
    }
}
