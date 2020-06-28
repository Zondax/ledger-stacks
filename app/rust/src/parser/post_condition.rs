use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::parser::parser_common::{
    u8_with_limits, AssetInfo, AssetInfoId, AssetName, ClarityName, ContractName, Hash160,
    ParserError, StacksAddress, MAX_STRING_LEN, NUM_SUPPORTED_POST_CONDITIONS,
};
use crate::parser::value::Value;

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
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let cond_type = le_u8(bytes)?;
        let principal = PostConditionPrincipal::from_bytes(cond_type.0)?;
        let res = match PostConditionType::from_u8(cond_type.1)
            .ok_or(ParserError::parser_invalid_post_condition)?
        {
            PostConditionType::STX => {
                let code = le_u8(principal.0)?;
                let fungible = FungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_fungible_code)?;
                let amount = be_u64(code.0)?;
                let condition = Self::STX(principal.1, fungible, amount.1);
                (amount.0, condition)
            }
            PostConditionType::FungibleToken => {
                let asset = AssetInfo::from_bytes(principal.0)?;
                let code = le_u8(asset.0)?;
                let fungible = FungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_fungible_code)?;
                let amount = be_u64(code.0)?;
                let condition = Self::Fungible(principal.1, asset.1, fungible, amount.1);
                (amount.0, condition)
            }
            PostConditionType::NonFungibleToken => {
                let asset = AssetInfo::from_bytes(principal.0)?;
                let name = Value::from_bytes(asset.0)?;
                let code = le_u8(name.0)?;
                let non_fungible = NonfungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_non_fungible_code)?;
                let condition = Self::Nonfungible(principal.1, asset.1, name.1, non_fungible);
                (code.0, condition)
            }
        };
        Ok(res)
    }

    pub fn num_items(&self) -> u8 {
        match *self {
            Self::STX(..) => 3,
            Self::Fungible(..) => 4,
            Self::Nonfungible(..) => 3,
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
        println!(
            "post-conditions size: {}",
            core::mem::size_of::<TransactionPostCondition>()
        );
        let hash = [1u8; 20];
        let hash160 = Hash160(hash.as_ref());
        let principal1 = PostConditionPrincipal::Standard(StacksAddress(1, hash160));
        let stx_pc1 =
            TransactionPostCondition::STX(principal1, FungibleConditionCode::SentGt, 12345);
        let bytes: Vec<u8> = vec![
            0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0, 0,
            0, 48, 57,
        ];
        let parsed1 = TransactionPostCondition::from_bytes(&bytes).unwrap().1;
        assert_eq!(stx_pc1, parsed1);

        let principal2 = PostConditionPrincipal::Contract(
            StacksAddress(2, Hash160([2u8; 20].as_ref())),
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
        let hash160 = Hash160(hash.as_ref());
        let addr = StacksAddress(1, hash160);
        let contract_name = ContractName(b"contract-name".as_ref());
        let asset_name = ClarityName(b"hello-asset".as_ref());
        let principal = PostConditionPrincipal::Standard(addr);
        let asset_info = AssetInfo {
            address: StacksAddress(1, Hash160([0xff; 20].as_ref())),
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

        let principal2 = PostConditionPrincipal::Contract(
            StacksAddress(2, Hash160([2u8; 20].as_ref())),
            ContractName(b"hello-world".as_ref()),
        );
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
