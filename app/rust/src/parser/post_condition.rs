use arrayvec::ArrayVec;
use core::fmt::{self, Write};
use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::parser::fp_uint64_to_str;
use crate::parser::parser_common::{
    u8_with_limits, AssetInfo, AssetInfoId, AssetName, ClarityName, ContractName, ParserError,
    StacksAddress, C32_ENCODED_ADDRS_LENGTH, MAX_STRING_LEN, NUM_SUPPORTED_POST_CONDITIONS,
    STX_DECIMALS,
};
use crate::parser::value::Value;
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
                let condition = PostConditionPrincipal::Contract(addrs.1, contract_name.1);
                Ok((contract_name.0, condition))
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
            Self::Standard(_) => true,
            _ => false,
        }
    }

    pub fn is_contract(&self) -> bool {
        match self {
            Self::Contract(_, _) => true,
            _ => false,
        }
    }

    #[inline(never)]
    pub fn origin_address(
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let mut output: ArrayVec<[_; C32_ENCODED_ADDRS_LENGTH]> = ArrayVec::new();
        output.try_extend_from_slice(b"Origin").unwrap();
        Ok(output)
    }

    #[inline(never)]
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

    pub fn check(self, amount_sent_condition: u128, amount_sent: u128) -> bool {
        match self {
            FungibleConditionCode::SentEq => amount_sent == amount_sent_condition,
            FungibleConditionCode::SentGt => amount_sent > amount_sent_condition,
            FungibleConditionCode::SentGe => amount_sent >= amount_sent_condition,
            FungibleConditionCode::SentLt => amount_sent < amount_sent_condition,
            FungibleConditionCode::SentLe => amount_sent <= amount_sent_condition,
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
pub enum TransactionPostConditionMode {
    Allow = 0x01, // allow any other changes not specified
    Deny = 0x02,  // deny any other changes not specified
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
    STX(PostConditionPrincipal<'a>, FungibleConditionCode, u64),
    Fungible(
        PostConditionPrincipal<'a>,
        AssetInfo<'a>,
        FungibleConditionCode,
        u64,
    ),
    Nonfungible(
        PostConditionPrincipal<'a>,
        AssetInfo<'a>,
        Value<'a>, // BlockStacks uses  Value, but the documentation says it is an asset-name
        NonfungibleConditionCode,
    ),
}

impl<'a> TransactionPostCondition<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let cond_type = le_u8(bytes)?;
        let principal = PostConditionPrincipal::from_bytes(cond_type.0)?;
        match PostConditionType::from_u8(cond_type.1)
            .ok_or(ParserError::parser_invalid_post_condition)?
        {
            PostConditionType::STX => {
                let code = le_u8(principal.0)?;
                let fungible = FungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_fungible_code)?;
                let amount = be_u64(code.0)?;
                let condition = Self::STX(principal.1, fungible, amount.1);
                Ok((amount.0, condition))
            }
            PostConditionType::FungibleToken => {
                let asset = AssetInfo::from_bytes(principal.0)?;
                let code = le_u8(asset.0)?;
                let fungible = FungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_fungible_code)?;
                let amount = be_u64(code.0)?;
                let condition = Self::Fungible(principal.1, asset.1, fungible, amount.1);
                Ok((amount.0, condition))
            }
            PostConditionType::NonFungibleToken => {
                let asset = AssetInfo::from_bytes(principal.0)?;
                let name = Value::from_bytes(asset.0)?;
                let code = le_u8(name.0)?;
                let non_fungible = NonfungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_non_fungible_code)?;
                let condition = Self::Nonfungible(principal.1, asset.1, name.1, non_fungible);
                Ok((code.0, condition))
            }
        }
    }

    #[inline(never)]
    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let cond_type = le_u8(bytes)?;
        let (raw, _) = PostConditionPrincipal::from_bytes(cond_type.0)?;
        let leftover = match PostConditionType::from_u8(cond_type.1)
            .ok_or(ParserError::parser_invalid_post_condition)?
        {
            PostConditionType::STX => {
                let (bytes, _) = take(9usize)(raw)?;
                bytes
            }
            PostConditionType::FungibleToken => {
                let (asset_raw, _) = AssetInfo::read_as_bytes(raw)?;
                let (bytes, _) = take(9usize)(asset_raw)?;
                bytes
            }
            PostConditionType::NonFungibleToken => {
                let (asset_raw, _) = AssetInfo::read_as_bytes(raw)?;
                let (name_raw, _) = Value::from_bytes(asset_raw)?;
                let (bytes, _) = le_u8(name_raw)?;
                bytes
            }
        };
        crate::check_canary!();
        Ok((leftover, bytes))
    }

    #[inline(never)]
    pub fn is_origin_principal(&self) -> bool {
        match self {
            Self::STX(ref principal, _, _)
            | Self::Fungible(ref principal, _, _, _)
            | Self::Nonfungible(ref principal, _, _, _) => principal.is_origin(),
        }
    }

    pub fn is_standard_principal(&self) -> bool {
        match self {
            Self::STX(ref principal, _, _)
            | Self::Fungible(ref principal, _, _, _)
            | Self::Nonfungible(ref principal, _, _, _) => principal.is_standard(),
        }
    }

    pub fn is_contract_principal(&self) -> bool {
        match self {
            Self::STX(ref principal, _, _)
            | Self::Fungible(ref principal, _, _, _)
            | Self::Nonfungible(ref principal, _, _, _) => principal.is_contract(),
        }
    }

    #[inline(never)]
    pub fn get_principal_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        match self {
            Self::STX(ref principal, _, _)
            | Self::Fungible(ref principal, _, _, _)
            | Self::Nonfungible(ref principal, _, _, _) => principal.get_principal_address(),
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
            Self::STX(_, _, amount) => Some(amount),
            Self::Fungible(_, _, _, amount) => Some(amount),
            _ => None,
        }
    }

    #[inline(never)]
    pub fn tokens_amount_str(&self) -> Option<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);

        let amount = match self {
            Self::Fungible(_, _, _, amount) => *amount,
            _ => return None,
        };
        let len = zxformat::u64_to_str(output.as_mut(), amount).ok()? as usize;
        unsafe {
            output.set_len(len);
        }
        Some(output)
    }

    pub fn amount_stx(&self) -> Option<u64> {
        match self {
            Self::STX(_, _, amount) => Some(*amount),
            _ => None,
        }
    }

    // Move the content of this function to its own
    #[inline(never)]
    pub fn amount_stx_str(&self) -> Option<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>> {
        let amount = match self {
            Self::STX(_, _, amount) => *amount,
            _ => return None,
        };
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
        let len =
            zxformat::fpu64_to_str_check_test(output.as_mut(), amount, STX_DECIMALS).ok()? as usize;
        unsafe {
            output.set_len(len);
        }
        Some(output)
    }

    pub fn fungible_condition_code(&self) -> Option<FungibleConditionCode> {
        match self {
            Self::STX(_, code, _) | Self::Fungible(_, _, code, _) => Some(*code),
            _ => None,
        }
    }

    pub fn non_fungible_condition_code(&self) -> Option<NonfungibleConditionCode> {
        match self {
            Self::Nonfungible(_, _, _, code) => Some(*code),
            _ => None,
        }
    }

    #[inline(never)]
    pub fn num_items(&self) -> u8 {
        match self {
            Self::STX(..) | Self::Nonfungible(..) => 3,
            Self::Fungible(..) => 4,
        }
    }

    #[inline(never)]
    pub fn write_principal_address(
        &self,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // The post condition principal address
        let mut writer_key = zxformat::Writer::new(out_key);
        writer_key
            .write_str("Principal")
            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
        let addr = self.get_principal_address()?;
        crate::check_canary!();
        zxformat::pageString(out_value, &addr[..addr.len()], page_idx)
    }

    #[inline(never)]
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

    #[inline(never)]
    pub fn get_stx_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::STX(_, code, _) => match display_idx {
                // PostCondition code
                1 => {
                    writer_key
                        .write_str("Fungi. Code")
                        .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                    crate::check_canary!();
                    zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                }
                // Amount in stx
                2 => {
                    writer_key
                        .write_str("STX amount")
                        .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                    let amount = self.amount_stx_str().unwrap();
                    crate::check_canary!();
                    zxformat::pageString(out_value, &amount[..amount.len()], page_idx)
                }
                _ => Err(ParserError::parser_display_idx_out_of_range),
            },
            _ => Err(ParserError::parser_unexpected_error),
        }
    }

    #[inline(never)]
    pub fn get_fungible_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Fungible(_, ref asset, code, _) => {
                match display_idx {
                    // Asset-name
                    1 => {
                        writer_key
                            .write_str("Asset name")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, asset.asset_name(), page_idx)
                    }
                    // Fungible code
                    2 => {
                        writer_key
                            .write_str("Fungi. Code")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                    }
                    // Amount of tokens
                    3 => {
                        writer_key
                            .write_str("Token amount")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        let token = self.tokens_amount_str().unwrap();
                        crate::check_canary!();
                        zxformat::pageString(out_value, &token[..token.len()], page_idx)
                    }
                    _ => Err(ParserError::parser_display_idx_out_of_range),
                }
            }
            _ => Err(ParserError::parser_unexpected_error),
        }
    }

    #[inline(never)]
    pub fn get_non_fungible_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        crate::bolos::c_zemu_log_stack(b"nonfungible\0");
        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Nonfungible(_, ref asset, _, code) => {
                match display_idx {
                    // Asset-name
                    1 => {
                        writer_key
                            .write_str("Asset name")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, asset.asset_name(), page_idx)
                    }
                    // Fungible code
                    2 => {
                        writer_key
                            .write_str("NonFungi. Code")
                            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                    }
                    _ => Err(ParserError::parser_display_idx_out_of_range),
                }
            }
            _ => Err(ParserError::parser_unexpected_error),
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
        let hash = [1u8; 20];

        let mut address = vec![1u8];
        address.extend_from_slice(hash.as_ref());

        let principal1 = PostConditionPrincipal::Standard(StacksAddress(address.as_ref()));
        let stx_pc1 =
            TransactionPostCondition::STX(principal1, FungibleConditionCode::SentGt, 12345);
        let bytes: Vec<u8> = vec![
            0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0,
            0, 48, 57,
        ];
        let parsed1 = TransactionPostCondition::from_bytes(&bytes).unwrap().1;
        assert_eq!(stx_pc1, parsed1);

        let mut address = vec![2u8];
        address.extend_from_slice([2u8; 20].as_ref());

        let principal2 = PostConditionPrincipal::Contract(
            StacksAddress(address.as_ref()),
            ContractName(b"hello-world".as_ref()),
        );
        let stx_pc2 =
            TransactionPostCondition::STX(principal2, FungibleConditionCode::SentGt, 12345);
        let bytes2: Vec<u8> = vec![
            0, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 11, 104, 101, 108,
            108, 111, 45, 119, 111, 114, 108, 100, 2, 0, 0, 0, 0, 0, 0, 48, 57,
        ];

        let parsed2 = TransactionPostCondition::from_bytes(&bytes2).unwrap().1;
        assert_eq!(stx_pc2, parsed2);
    }

    #[test]
    fn test_fungible_postcondition() {
        let hash = [0x01; 20];
        let mut address = vec![1u8];
        address.extend_from_slice(hash.as_ref());

        let addr = StacksAddress(address.as_ref());
        let contract_name = ContractName(b"contract-name".as_ref());
        let asset_name = ClarityName(b"hello-asset".as_ref());
        let principal = PostConditionPrincipal::Standard(addr);

        let mut address2 = vec![1u8];
        address2.extend_from_slice([0xff; 20].as_ref());
        let address2 = StacksAddress(address2.as_ref());
        let asset_info = AssetInfo {
            address: address2,
            contract_name,
            asset_name,
        };
        let fungible_pc = TransactionPostCondition::Fungible(
            principal,
            asset_info,
            FungibleConditionCode::SentGt,
            23456,
        );
        let bytes = vec![
            1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            13, 99, 111, 110, 116, 114, 97, 99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108, 108,
            111, 45, 97, 115, 115, 101, 116, 2, 0, 0, 0, 0, 0, 0, 91, 160,
        ];

        let parsed = TransactionPostCondition::from_bytes(&bytes).unwrap().1;
        assert_eq!(fungible_pc, parsed);

        let mut address = vec![2u8];
        address.extend_from_slice([2u8; 20].as_ref());

        let addr = StacksAddress(address.as_ref());
        let principal2 =
            PostConditionPrincipal::Contract(addr, ContractName(b"hello-world".as_ref()));
        let fungible_pc2 = TransactionPostCondition::Fungible(
            principal2,
            asset_info,
            FungibleConditionCode::SentGt,
            23456,
        );
        let bytes2 = vec![
            1, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 11, 104, 101, 108,
            108, 111, 45, 119, 111, 114, 108, 100, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 13, 99, 111, 110, 116, 114, 97,
            99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108, 108, 111, 45, 97, 115, 115, 101,
            116, 2, 0, 0, 0, 0, 0, 0, 91, 160,
        ];
        let parsed2 = TransactionPostCondition::from_bytes(&bytes2).unwrap().1;
        assert_eq!(fungible_pc2, parsed2);
    }

    #[test]
    fn test_nonfungible_postcondition() {}
}
