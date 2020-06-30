#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{be_u32, le_u32, le_u64, le_u8},
};

use crate::parser::c32;

// The max len for asset, contract and clarity names
pub const MAX_STRING_LEN: u8 = 128;
pub const HASH160_LEN: usize = 20;

// The amount of post_conditions we can
// handle
pub const NUM_SUPPORTED_POST_CONDITIONS: usize = 16;
pub const SIGNATURE_LEN: usize = 65;
pub const MAX_STACKS_STRING_LEN: usize = 256;
pub const TOKEN_TRANSFER_MEMO_LEN: usize = 34;

/// Stacks transaction versions
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

impl TransactionVersion {
    #[inline(never)]
    pub fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let version_res = le_u8(bytes)?;
        let tx_version =
            Self::from_u8(version_res.1).ok_or(ParserError::parser_unexpected_error)?;
        Ok((version_res.0, tx_version))
    }

    #[inline(never)]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy, Debug)]
pub enum AssetInfoId {
    STX = 0,
    FungibleAsset = 1,
    NonfungibleAsset = 2,
}

impl AssetInfoId {
    #[inline(never)]
    pub fn from_u8(b: u8) -> Option<AssetInfoId> {
        match b {
            0 => Some(AssetInfoId::STX),
            1 => Some(AssetInfoId::FungibleAsset),
            2 => Some(AssetInfoId::NonfungibleAsset),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AssetInfo<'a> {
    pub address: StacksAddress<'a>,
    pub contract_name: ContractName<'a>,
    pub asset_name: ClarityName<'a>,
}

impl<'a> AssetInfo<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let address = StacksAddress::from_bytes(bytes)?;
        let contract_name = ContractName::from_bytes(address.0)?;
        let asset_name = ClarityName::from_bytes(contract_name.0)?;
        Ok((
            asset_name.0,
            Self {
                address: address.1,
                contract_name: contract_name.1,
                asset_name: asset_name.1,
            },
        ))
    }
}

#[repr(u32)]
#[no_mangle]
#[derive(Copy, Clone, Debug)]
/// ParserError is the counterpart of
/// the parse_error_t in c,
/// we redeclare it here, just for interpolation
/// purposes
pub enum ParserError {
    // Generic errors
    parser_ok = 0,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexpected_error,
    parser_no_memory_for_state,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    // Required fields
    // Coin specific
    parser_post_condition_failed,
    parser_invalid_contract_name,
    parser_invalid_asset_name,
    parser_invalid_clarity_name,
    parser_invalid_fungible_code,
    parser_invalid_non_fungible_code,
    parser_invalid_asset_info,
    parser_invalid_post_condition,
    parser_invalid_post_condition_principal,
    parser_invalid_hash_mode,
    parser_invalid_signature,
    parser_invalid_pubkey_encoding,
    parser_invalid_auth_type,
    parser_invalid_argument_id,
    parser_invalid_token_transfer_principal,
    parser_invalid_transaction_payload,
    parser_invalid_address_version,
    parser_stacks_string_too_long,
    parser_unexpected_type,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_value_out_of_range,
    parser_invalid_address,
    parser_invalid_token_transfer_type,
}

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::parser_unexpected_buffer_end,
            ErrorKind::Permutation => ParserError::parser_unexpected_type,
            ErrorKind::TooLarge => ParserError::parser_value_out_of_range,
            _ => ParserError::parser_unexpected_error,
        }
    }
}

impl<I> nom::error::ParseError<I> for ParserError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Self::from(kind)
    }

    // We don't have enough memory resources to use here an array with the last
    // N errors to be used as a backtrace, so that, we just propagate here the latest
    // reported error
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
impl From<ParserError> for nom::Err<ParserError> {
    fn from(error: ParserError) -> Self {
        nom::Err::Error(error)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hash160<'a>(pub &'a [u8]);

impl<'a> Hash160<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let name = take(HASH160_LEN)(bytes)?;
        Ok((name.0, Self(name.1)))
    }

    pub fn to_mainnet_address(
        &self,
        mode: HashMode,
    ) -> Result<arrayvec::ArrayVec<[u8; 64]>, ParserError> {
        c32::c32_address(mode.to_version_mainnet(), self.0)
    }

    pub fn to_testnet_address(
        &self,
        mode: HashMode,
    ) -> Result<arrayvec::ArrayVec<[u8; 64]>, ParserError> {
        c32::c32_address(mode.to_version_testnet(), self.0)
    }
}

// tag address hash modes as "singlesig" or "multisig" so we can't accidentally construct an
// invalid spending condition
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashMode {
    //  A single public key is used. Hash it like a Bitcoin P2PKH output.
    P2PKH = 0x00, // hash160(public-key)
    P2SH = 0x01,  // hash160(multisig-red)
    //  A single public key is used. Hash it like a Bitcoin P2WPKH-P2SH output.
    P2WPKH = 0x02, // hash160(segwit-progr)
    P2WSH = 0x03,  // hash160(segwit-prog)
}

impl HashMode {
    #[inline(never)]
    pub fn from_u8(n: u8) -> Option<HashMode> {
        match n {
            x if x == HashMode::P2PKH as u8 => Some(HashMode::P2PKH),
            x if x == HashMode::P2WPKH as u8 => Some(HashMode::P2WPKH),
            _ => None,
        }
    }

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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StacksString<'a>(&'a [u8]);

impl<'a> StacksString<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = be_u32(bytes)?;
        let string_len = len.1 as usize;
        if string_len > MAX_STACKS_STRING_LEN {
            return Err(nom::Err::Error(ParserError::parser_stacks_string_too_long));
        }
        let string = take(string_len)(len.0)?;
        Ok((string.0, Self(string.1)))
    }
}

// contract name with valid charactes being
// ^[a-zA-Z]([a-zA-Z0-9]|[-_])*$
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ContractName<'a>(pub &'a [u8]);

impl<'a> ContractName<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = u8_with_limits(MAX_STRING_LEN, bytes)
            .map_err(|_| ParserError::parser_invalid_contract_name)?;
        let nameLen = len.1;
        let name = take(nameLen as usize)(len.0)?;
        // TODO: Verify if the name has valid characters
        Ok((name.0, Self(name.1)))
    }
}

// Represent a clarity contract name with valid characters being
// ^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClarityName<'a>(pub &'a [u8]);

impl<'a> ClarityName<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = u8_with_limits(MAX_STRING_LEN, bytes)
            .map_err(|_| ParserError::parser_invalid_asset_name)?;
        let nameLen = len.1;
        let name = take(nameLen as usize)(len.0)?;
        // TODO: Verify if the name has valid characters
        Ok((name.0, Self(name.1)))
    }
}

// An Asset name
// ^[a-zA-Z]([a-zA-Z0-9]|[-_!?])*$
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AssetName<'a>(pub &'a [u8]);

impl<'a> AssetName<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = u8_with_limits(MAX_STRING_LEN, bytes)
            .map_err(|_| ParserError::parser_invalid_asset_name)?;
        let nameLen = len.1;
        let name = take(nameLen as usize)(len.0)?;
        // TODO: Verify if the name has valid characters
        Ok((name.0, Self(name.1)))
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StacksAddress<'a>(pub u8, pub Hash160<'a>);

impl<'a> StacksAddress<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let addrId = le_u8(bytes)?;
        let address = take(HASH160_LEN)(addrId.0)?;
        Ok((address.0, Self(addrId.1, Hash160(address.1))))
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ContractPrincipal<'a>(StandardPrincipal<'a>, ContractName<'a>);
impl<'a> ContractPrincipal<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let address = StandardPrincipal::from_bytes(bytes)?;
        let name = ContractName::from_bytes(address.0)?;
        Ok((name.0, Self(address.1, name.1)))
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StandardPrincipal<'a>(pub u8, pub &'a [u8]);

impl<'a> StandardPrincipal<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let addrId = le_u8(bytes)?;
        let address = take(HASH160_LEN)(addrId.0)?;
        Ok((address.0, Self(addrId.1, address.1)))
    }
}

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PrincipalData<'a> {
    Standard(StandardPrincipal<'a>),
    Contract(ContractPrincipal<'a>),
}

impl<'a> PrincipalData<'a> {
    #[inline(never)]
    pub fn standard_from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let principal = StandardPrincipal::from_bytes(bytes)?;
        Ok((principal.0, Self::Standard(principal.1)))
    }

    #[inline(never)]
    pub fn contract_principal_from_bytes(
        bytes: &'a [u8],
    ) -> nom::IResult<&[u8], Self, ParserError> {
        let principal = ContractPrincipal::from_bytes(bytes)?;
        Ok((principal.0, Self::Contract(principal.1)))
    }

    pub fn version(&self) -> u8 {
        match *self {
            Self::Standard(ref principal) => principal.0,
            Self::Contract(ref principal) => (principal.0).0,
        }
    }

    pub fn raw_address(&self) -> &[u8] {
        match *self {
            Self::Standard(ref principal) => principal.1,
            Self::Contract(ref principal) => (principal.0).1,
        }
    }

    pub fn encoded_address(&self) -> Result<arrayvec::ArrayVec<[u8; 64]>, ParserError> {
        let version = self.version();
        let raw = self.raw_address();
        c32::c32_address(version, raw)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TokenTransferMemo<'a>(pub &'a [u8]);

impl<'a> TokenTransferMemo<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let memo = take(TOKEN_TRANSFER_MEMO_LEN)(bytes)?;
        Ok((memo.0, Self(memo.1)))
    }

    // returns a non null byte array with the memo
    // content
    pub fn memo(&self) -> &[u8] {
        self.0
    }
}

/******************************* NOM parser combinators *******************************************/

pub fn u8_with_limits(limit: u8, bytes: &[u8]) -> nom::IResult<&[u8], u8, ParserError> {
    if !bytes.is_empty() && bytes[0] <= limit {
        map_parser(take(1usize), le_u8)(bytes)
    } else {
        Err(nom::Err::Error(ParserError::parser_value_out_of_range))
    }
}
