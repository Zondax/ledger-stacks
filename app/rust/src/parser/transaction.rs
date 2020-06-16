use core::fmt::{self, Write};
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{be_u32, le_u64, le_u8},
};

use crate::parser::{
    parser_common::*, post_condition::TransactionPostCondition, transaction_auth::TransactionAuth,
    transaction_payload::TransactionPayload, value::Value,
};

use crate::zxformat;

/// Stacks transaction versions
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionVersion {
    Mainnet = 0x00,
    Testnet = 0x80,
}

impl TransactionVersion {
    fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let version_res = le_u8(bytes)?;
        let tx_version =
            Self::from_u8(version_res.1).ok_or(ParserError::parser_unexpected_error)?;
        Ok((version_res.0, tx_version))
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPostConditionMode {
    Allow = 0x01, // allow any other changes not specified
    Deny = 0x02,  // deny any other changes not specified
}

impl TransactionPostConditionMode {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Allow),
            2 => Some(Self::Deny),
            _ => None,
        }
    }

    fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let mode = le_u8(bytes)?;
        let tx_mode = Self::from_u8(mode.1).ok_or(ParserError::parser_unexpected_error)?;
        Ok((mode.0, tx_mode))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,  // must be included in a StacksBlock
    OffChainOnly = 2, // must be included in a StacksMicroBlock
    Any = 3,          // either
}

impl TransactionAnchorMode {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::OnChainOnly),
            2 => Some(Self::OffChainOnly),
            3 => Some(Self::Any),
            _ => None,
        }
    }

    fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let mode = le_u8(bytes)?;
        let tx_mode = Self::from_u8(mode.1).ok_or(ParserError::parser_unexpected_error)?;
        Ok((mode.0, tx_mode))
    }
}

#[repr(C)]
pub struct PostConditions<'a> {
    pub len: usize, // Number of post-conditions
    conditions: [Option<TransactionPostCondition<'a>>; NUM_SUPPORTED_POST_CONDITIONS],
}

impl<'a> PostConditions<'a> {
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = be_u32(bytes)?;
        let mut conditions: [Option<TransactionPostCondition<'a>>; NUM_SUPPORTED_POST_CONDITIONS] =
            [None; NUM_SUPPORTED_POST_CONDITIONS];
        let mut iter = iterator(len.0, TransactionPostCondition::from_bytes);
        iter.take(len.1 as _)
            .enumerate()
            .zip(conditions.iter_mut())
            .for_each(|i| {
                *i.1 = Some((i.0).1);
            });
        let res = iter.finish()?;
        Ok((
            res.0,
            Self {
                len: len.1 as usize,
                conditions,
            },
        ))
    }
}

pub type TxTuple<'a> = (
    TransactionVersion, // version number
    u32,                // chainId
    TransactionAuth<'a>,
    TransactionAnchorMode,
    TransactionPostConditionMode, // u8
    PostConditions<'a>,
    TransactionPayload<'a>,
);

impl<'a> From<TxTuple<'a>> for Transaction<'a> {
    fn from(raw: TxTuple<'a>) -> Self {
        Self {
            version: raw.0,
            chain_id: raw.1,
            transaction_auth: raw.2,
            anchor_mode: raw.3,
            post_condition_mode: raw.4,
            post_conditions: raw.5,
            payload: raw.6,
        }
    }
}

#[repr(C)]
pub struct Transaction<'a> {
    pub version: TransactionVersion,
    pub chain_id: u32,
    transaction_auth: TransactionAuth<'a>,
    anchor_mode: TransactionAnchorMode,
    post_condition_mode: TransactionPostConditionMode,
    post_conditions: PostConditions<'a>,
    payload: TransactionPayload<'a>,
}

impl<'a> Transaction<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParserError> {
        match permutation((
            TransactionVersion::from_bytes,
            be_u32,
            TransactionAuth::from_bytes,
            TransactionAnchorMode::from_bytes,
            TransactionPostConditionMode::from_bytes,
            PostConditions::from_bytes,
            TransactionPayload::from_bytes,
        ))(bytes)
        {
            Ok(tx) => Ok(Self::from(tx.1)),
            Err(_e) => Err(ParserError::parser_unexpected_error),
        }
    }

    #[allow(unused)]
    pub fn get_item(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        Ok(0)
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
}
