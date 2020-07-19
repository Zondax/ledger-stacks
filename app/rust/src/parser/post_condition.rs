use arrayvec::ArrayVec;
use core::fmt::{self, Write};
use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::parser::parser_common::{
    u8_with_limits, AssetInfo, AssetInfoId, ClarityName, ContractName, ParserError, StacksAddress,
    C32_ENCODED_ADDRS_LENGTH, HASH160_LEN, MAX_STRING_LEN, NUM_SUPPORTED_POST_CONDITIONS,
    STX_DECIMALS,
};
use crate::parser::{c32, fp_uint64_to_str, value::Value};
use crate::zxformat;

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum PostConditionPrincipalId {
    Origin = 0x01,
    Standard = 0x02,
    Contract = 0x03,
}

impl PostConditionPrincipalId {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Origin),
            2 => Some(Self::Standard),
            3 => Some(Self::Contract),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PostConditionPrincipal<'a> {
    Origin,
    Standard(StacksAddress<'a>),
    Contract(StacksAddress<'a>, ContractName<'a>),
}

impl<'a> PostConditionPrincipal<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let principal_id = PostConditionPrincipalId::from_u8(id.1)
            .ok_or(ParserError::parser_invalid_post_condition_principal)?;
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
        let id = le_u8(bytes)?;
        let principal_id = PostConditionPrincipalId::from_u8(id.1)
            .ok_or(ParserError::parser_invalid_post_condition_principal)?;
        match principal_id {
            PostConditionPrincipalId::Origin => Ok((id.0, Default::default())),
            PostConditionPrincipalId::Standard => {
                // we take 20-byte key hash + 1-byte hash_mode + 1-byte principal_id
                let (raw, addr) = take(HASH160_LEN + 2usize)(bytes)?;
                Ok((raw, addr))
            }
            PostConditionPrincipalId::Contract => {
                let (raw, _) = StacksAddress::from_bytes(id.0)?;
                let (raw2, name) = ContractName::from_bytes(raw)?;
                // we take 20-byte key hash + 1-byte hash_mode +
                // contract_name len + 1-byte len + 1-byte principal_id
                let total_len = HASH160_LEN + name.0.len() + 3;
                let (_, contract_bytes) = take(total_len)(bytes)?;
                Ok((raw2, contract_bytes))
            }
        }
    }

    pub fn is_origin(&self) -> bool {
        match self {
            Self::Origin => true,
            _ => false,
        }
    }

    pub fn is_standard(&self) -> bool {
        match self {
            Self::Standard(..) => true,
            _ => false,
        }
    }

    pub fn is_contract(&self) -> bool {
        match self {
            Self::Contract(..) => true,
            _ => false,
        }
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

    pub fn get_contract_name(&self) -> Option<&'a [u8]> {
        match self {
            Self::Contract(_, ref name) => Some(name.0),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy, Debug)]
pub enum FungibleConditionCode {
    SentEq = 0x01,
    SentGt = 0x02,
    SentGe = 0x03,
    SentLt = 0x04,
    SentLe = 0x05,
}

impl FungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<FungibleConditionCode> {
        match b {
            0x01 => Some(FungibleConditionCode::SentEq),
            0x02 => Some(FungibleConditionCode::SentGt),
            0x03 => Some(FungibleConditionCode::SentGe),
            0x04 => Some(FungibleConditionCode::SentLt),
            0x05 => Some(FungibleConditionCode::SentLe),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            FungibleConditionCode::SentEq => "SentEq",
            FungibleConditionCode::SentGt => "SentGt",
            FungibleConditionCode::SentGe => "SentGe",
            FungibleConditionCode::SentLt => "SentLt",
            FungibleConditionCode::SentLe => "SentLe",
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy, Debug)]
pub enum NonfungibleConditionCode {
    Sent = 0x10,
    NotSent = 0x11,
}

impl NonfungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<NonfungibleConditionCode> {
        match b {
            0x10 => Some(NonfungibleConditionCode::Sent),
            0x11 => Some(NonfungibleConditionCode::NotSent),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            Self::Sent => "Sent",
            Self::NotSent => "NotSent",
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum PostConditionType {
    STX = 0,
    FungibleToken = 1,
    NonFungibleToken = 2,
}

impl PostConditionType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::STX),
            1 => Some(Self::FungibleToken),
            2 => Some(Self::NonFungibleToken),
            _ => None,
        }
    }
}

/// Post-condition on a transaction
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransactionPostCondition<'a> {
    STX(&'a [u8]),
    Fungible(&'a [u8]),
    Nonfungible(&'a [u8]),
}

impl<'a> TransactionPostCondition<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, cond_type) = le_u8(bytes)?;
        let principal = PostConditionPrincipal::read_as_bytes(raw)?;
        let principal_len = raw.len() - principal.0.len();

        match PostConditionType::from_u8(cond_type)
            .ok_or(ParserError::parser_invalid_post_condition)?
        {
            PostConditionType::STX => {
                let len = principal_len + 1 + 8;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::STX(inner)))
            }
            PostConditionType::FungibleToken => {
                let asset = AssetInfo::read_as_bytes(principal.0)?;
                let len = principal_len + asset.1.len() + 1 + 8;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Fungible(inner)))
            }
            PostConditionType::NonFungibleToken => {
                let asset = AssetInfo::read_as_bytes(principal.0)?;
                let value_len = Value::value_len(asset.0)?;
                let len = principal_len + asset.1.len() + value_len + 1;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Nonfungible(inner)))
            }
        }
    }

    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let cond_type = le_u8(bytes)?;
        let (raw, _) = PostConditionPrincipal::read_as_bytes(cond_type.0)?;
        let mut len = bytes.len() - raw.len();
        len += match PostConditionType::from_u8(cond_type.1)
            .ok_or(ParserError::parser_invalid_post_condition)?
        {
            PostConditionType::STX => {
                // We take 9-bytes which comprises the 8-byte amount + 1-byte fungible code
                9usize
            }
            PostConditionType::FungibleToken => {
                let (_, asset) = AssetInfo::read_as_bytes(raw)?;
                // We take 9-bytes which containf the 8-byte amount + 1-byte fungible code
                asset.len() + 9
            }
            PostConditionType::NonFungibleToken => {
                let (asset_raw, asset) = AssetInfo::read_as_bytes(raw)?;
                let value_len = Value::value_len(asset_raw)?;
                asset.len() + value_len + 1
            }
        };
        crate::check_canary!();
        take(len)(bytes)
    }

    pub fn is_origin_principal(&self) -> bool {
        match self {
            Self::STX(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                principal[0] == PostConditionPrincipalId::Origin as u8
            }
        }
    }

    pub fn is_standard_principal(&self) -> bool {
        match self {
            Self::STX(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                principal[0] == PostConditionPrincipalId::Standard as u8
            }
        }
    }

    pub fn is_contract_principal(&self) -> bool {
        match self {
            Self::STX(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                principal[0] == PostConditionPrincipalId::Origin as u8
            }
        }
    }

    #[inline(never)]
    pub fn get_principal_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        match self {
            Self::STX(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                let (_, principal) = PostConditionPrincipal::from_bytes(&principal)
                    .map_err(|_| ParserError::parser_invalid_post_condition)?;
                principal.get_principal_address()
            }
        }
    }

    pub fn is_stx(&self) -> bool {
        match self {
            Self::STX(..) => true,
            _ => false,
        }
    }

    pub fn is_fungible(&self) -> bool {
        match self {
            Self::Fungible(..) => true,
            _ => false,
        }
    }

    pub fn is_non_fungible(&self) -> bool {
        match self {
            Self::Nonfungible(..) => true,
            _ => false,
        }
    }

    pub fn tokens_amount(&self) -> Option<u64> {
        match *self {
            Self::STX(inner) | Self::Fungible(inner) => {
                let at = inner.len() - 8;
                be_u64::<'a, ParserError>(&inner[at..])
                    .map(|res| res.1)
                    .ok()
            }
            _ => None,
        }
    }

    pub fn amount_stx(&self) -> Option<u64> {
        match self {
            Self::STX(inner) => {
                let at = inner.len() - 8;
                be_u64::<'a, ParserError>(&inner[at..])
                    .map(|res| res.1)
                    .ok()
            }
            _ => None,
        }
    }

    pub fn tokens_amount_str(&self) -> Option<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);

        let amount = self.tokens_amount()?;
        let len = zxformat::u64_to_str(output.as_mut(), amount).ok()? as usize;
        unsafe {
            output.set_len(len);
        }
        Some(output)
    }

    pub fn amount_stx_str(&self) -> Option<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>> {
        let amount = self.amount_stx()?;
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
        let len =
            zxformat::fpu64_to_str_check_test(output.as_mut(), amount, STX_DECIMALS).ok()? as usize;
        unsafe {
            output.set_len(len);
        }
        Some(output)
    }

    pub fn fungible_condition_code(&self) -> Option<FungibleConditionCode> {
        let code = match self {
            Self::STX(inner) | Self::Fungible(inner) => inner[inner.len() - 9], // TODO: comment this 9
            _ => return None,
        };
        FungibleConditionCode::from_u8(code)
    }

    pub fn non_fungible_condition_code(&self) -> Option<NonfungibleConditionCode> {
        let code = match self {
            Self::Nonfungible(inner) => inner[inner.len() - 1],
            _ => return None,
        };
        NonfungibleConditionCode::from_u8(code)
    }

    pub fn asset_name(&self) -> Option<&[u8]> {
        match self {
            Self::Fungible(inner) | Self::Nonfungible(inner) => {
                PostConditionPrincipal::from_bytes(inner)
                    .and_then(|res| AssetInfo::from_bytes(res.0))
                    .map(|res| res.1.asset_name.0)
                    .ok()
            }
            _ => None,
        }
    }

    pub fn num_items(&self) -> u8 {
        match self {
            Self::STX(..) | Self::Nonfungible(..) => 3,
            Self::Fungible(..) => 4,
        }
    }

    pub fn write_principal_address(
        &self,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // The post condition principal address
        {
            let mut writer_key = zxformat::Writer::new(out_key);
            writer_key
                .write_str("Principal")
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
        }
        let addr = self.get_principal_address()?;
        let rs = zxformat::pageString(out_value, addr.as_ref(), page_idx);
        //crate::check_canary!();
        rs
    }

    pub fn get_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let index = display_idx % self.num_items();
        if index == 0 {
            self.write_principal_address(out_key, out_value, page_idx)
        } else {
            match self {
                Self::STX(..) => self.get_stx_items(index, out_key, out_value, page_idx),
                Self::Fungible(..) => self.get_fungible_items(index, out_key, out_value, page_idx),
                Self::Nonfungible(..) => {
                    self.get_non_fungible_items(index, out_key, out_value, page_idx)
                }
            }
        }
    }

    pub fn get_stx_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::STX(..) => match display_idx {
                // PostCondition code
                1 => {
                    writer_key
                        .write_str("Fungi. Code")
                        .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                    let code = self
                        .fungible_condition_code()
                        .ok_or(ParserError::parser_invalid_fungible_code)?;
                    zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                }
                // Amount in stx
                2 => {
                    writer_key
                        .write_str("STX amount")
                        .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                    let amount = self.amount_stx_str().unwrap();
                    zxformat::pageString(out_value, &amount[..amount.len()], page_idx)
                }
                _ => Err(ParserError::parser_display_idx_out_of_range),
            },
            _ => Err(ParserError::parser_unexpected_error),
        }
    }

    pub fn get_fungible_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Fungible(..) => {
                match display_idx {
                    // Asset-name
                    1 => {
                        writer_key
                            .write_str("Asset name")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        let name = self
                            .asset_name()
                            .ok_or(ParserError::parser_invalid_asset_name)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, name, page_idx)
                    }
                    // Fungible code
                    2 => {
                        writer_key
                            .write_str("Fungi. Code")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        let code = self
                            .fungible_condition_code()
                            .ok_or(ParserError::parser_invalid_fungible_code)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                    }
                    // Amount of tokens
                    3 => {
                        writer_key
                            .write_str("Token amount")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        let token = self
                            .tokens_amount_str()
                            .ok_or(ParserError::parser_unexpected_value)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, &token[..token.len()], page_idx)
                    }
                    _ => Err(ParserError::parser_display_idx_out_of_range),
                }
            }
            _ => Err(ParserError::parser_unexpected_error),
        }
    }

    pub fn get_non_fungible_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Nonfungible(..) => {
                match display_idx {
                    // Asset-name
                    1 => {
                        writer_key
                            .write_str("Asset name")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        let name = self
                            .asset_name()
                            .ok_or(ParserError::parser_invalid_asset_name)?;
                        zxformat::pageString(out_value, name, page_idx)
                    }
                    // Fungible code
                    2 => {
                        writer_key
                            .write_str("NonFungi. Code")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        let code = self
                            .non_fungible_condition_code()
                            .ok_or(ParserError::parser_invalid_non_fungible_code)?;
                        zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                    }
                    _ => Err(ParserError::parser_display_idx_out_of_range),
                }
            }
            _ => Err(ParserError::parser_unexpected_error),
        }
    }

    #[cfg(test)]
    pub fn get_inner_bytes(&self) -> &[u8] {
        match self {
            Self::STX(inner) | Self::Fungible(inner) | Self::Nonfungible(inner) => inner,
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use serde::{Deserialize, Serialize};
    use serde_json::{Result, Value};

    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::string::String;
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn test_stx_postcondition() {
        let bytes = [
            0u8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0,
            0, 0, 48, 57,
        ];
        let parsed1 = TransactionPostCondition::from_bytes(bytes.as_ref())
            .unwrap()
            .1;
        assert!(parsed1.is_stx());
        assert_eq!(parsed1.amount_stx().unwrap(), 12345);
        assert_eq!(
            parsed1.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed1.get_inner_bytes(), &bytes[1..]);

        let bytes2 = [
            0u8, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 11, 104, 101,
            108, 108, 111, 45, 119, 111, 114, 108, 100, 2, 0, 0, 0, 0, 0, 0, 48, 57,
        ];

        let parsed2 = TransactionPostCondition::from_bytes(bytes2.as_ref())
            .unwrap()
            .1;
        assert!(parsed2.is_stx());
        assert_eq!(parsed2.amount_stx().unwrap(), 12345);
        assert_eq!(
            parsed2.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed2.get_inner_bytes(), &bytes2[1..]);
    }

    #[test]
    fn test_fungible_postcondition() {
        let bytes = [
            1u8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 13, 99, 111, 110, 116, 114, 97, 99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108,
            108, 111, 45, 97, 115, 115, 101, 116, 2, 0, 0, 0, 0, 0, 0, 91, 160,
        ];

        let parsed = TransactionPostCondition::from_bytes(bytes.as_ref())
            .unwrap()
            .1;
        assert!(parsed.is_fungible());
        assert_eq!(parsed.get_inner_bytes(), &bytes[1..]);
        assert_eq!(
            parsed.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed.asset_name().unwrap(), b"hello-asset".as_ref());
        assert_eq!(parsed.tokens_amount().unwrap(), 23456);

        let mut address = vec![2u8];
        address.extend_from_slice([2u8; 20].as_ref());

        let addr = StacksAddress(address.as_ref());
        let mut principal = vec![3u8];
        principal.extend_from_slice(addr.0);
        principal.push(11u8); // contract_name len
        principal.extend_from_slice(b"hello-world".as_ref());
        let bytes2 = [
            1u8, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 11, 104, 101,
            108, 108, 111, 45, 119, 111, 114, 108, 100, 1, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 13, 99, 111, 110, 116, 114,
            97, 99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108, 108, 111, 45, 97, 115, 115, 101,
            116, 2, 0, 0, 0, 0, 0, 0, 91, 160,
        ];
        let parsed2 = TransactionPostCondition::from_bytes(bytes2.as_ref())
            .unwrap()
            .1;
        assert!(parsed2.is_fungible());
        assert_eq!(parsed2.get_inner_bytes(), &bytes2[1..]);
        assert_eq!(
            parsed2.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed2.asset_name().unwrap(), b"hello-asset".as_ref());
        assert_eq!(parsed2.tokens_amount().unwrap(), 23456);
    }
}
