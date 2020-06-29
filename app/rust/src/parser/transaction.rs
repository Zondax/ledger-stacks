use core::fmt::{self, Write};
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{be_u32, le_u64, le_u8},
};

use arrayvec::ArrayVec;

use crate::parser::{
    parser_common::*, post_condition::TransactionPostCondition, transaction_auth::TransactionAuth,
    transaction_payload::TransactionPayload, value::Value,
};

use crate::parser::ffi::fp_uint64_to_str;

use crate::zxformat;

use crate::check_canary;

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
        check_canary!();
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
        check_canary!();
        Ok((mode.0, tx_mode))
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
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
        check_canary!();
        Ok((
            res.0,
            Self {
                len: len.1 as usize,
                conditions,
            },
        ))
    }

    fn num_items(&self) -> u8 {
        let mut num = 0;
        // Iterates over valid values
        for p in self.conditions[..self.len].iter() {
            num += p.map(|post| post.num_items()).unwrap();
        }
        num
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
#[derive(Debug)]
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
            Ok(tx) => {
                // Note that if a transaction contains a token-transfer payload,
                // it MUST have only a standard authorization field. It cannot be sponsored.
                if (tx.1).6.is_token_transfer_payload() && !(tx.1).2.is_standard_auth() {
                    return Err(ParserError::parser_invalid_transaction_payload);
                }
                Ok(Self::from(tx.1))
            }
            Err(_e) => Err(ParserError::parser_unexpected_error),
        }
    }

    pub fn payload_recipient_address(&self) -> Option<arrayvec::ArrayVec<[u8; 64]>> {
        self.payload.recipient_address()
    }

    pub fn num_items(&self) -> u8 {
        // nonce + origin + fee-rate + payload + post-conditions
        3 + self.payload.num_items() + self.post_conditions.num_items()
    }

    fn get_origin_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);
        let origin = self.transaction_auth.origin();

        match display_idx {
            // The address of who signed this transaction
            0 => {
                writer_key
                    .write_str("Origin")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let origin_address = origin.signer_address(self.version)?;
                zxformat::pageString(out_value, origin_address.as_ref(), page_idx)
            }
            // The signer nonce
            1 => {
                writer_key
                    .write_str("Nonce")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let nonce_str = origin.nonce_str()?;
                zxformat::pageString(out_value, nonce_str.as_ref(), page_idx)
            }
            // The signer fee-rate
            2 => {
                writer_key
                    .write_str("Fee")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let fee_str = origin.fee_str()?;
                zxformat::pageString(out_value, fee_str.as_ref(), page_idx)
            }

            _ => unimplemented!(),
        }
    }

    fn get_other_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // 1. Format payloads
        if display_idx < (self.num_items() - self.post_conditions.num_items()) {
            self.payload
                .get_items(display_idx, out_key, out_value, page_idx)
        } else {
            // 2. Format Post-conditions
            Ok(0)
        }
    }

    pub fn get_item(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx >= self.num_items() {
            return Err(ParserError::parser_display_idx_out_of_range);
        }

        if display_idx < 3 {
            self.get_origin_items(display_idx, out_key, out_value, page_idx)
        } else {
            self.get_other_items(display_idx, out_key, out_value, page_idx)
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

    #[derive(Serialize, Deserialize)]
    struct StxTransaction {
        raw: String,
        recipient: String,
        sender: String,
        nonce: u64,
        amount: u64,
        fee: u32,
    }

    #[test]
    fn test_token_stx_transfer() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("stx_token_transfer");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: StxTransaction = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw).unwrap();
        let transaction = Transaction::from_bytes(&bytes).unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce);
        assert_eq!(json.fee, spending_condition.fee_rate as u32);

        let origin = spending_condition
            .signer_address(transaction.version)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(&json.sender, origin);

        let recipient = transaction.payload_recipient_address().unwrap();
        let addr_len = recipient.len();
        let address = core::str::from_utf8(&recipient[0..addr_len]).unwrap();
        assert_eq!(&json.recipient, address);
    }

    #[test]
    fn test_token_stx_transfer_testnet() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("stx_token_transfer_testnet");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: StxTransaction = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw).unwrap();
        let transaction = Transaction::from_bytes(&bytes).unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce);
        assert_eq!(json.fee, spending_condition.fee_rate as u32);

        let origin = spending_condition
            .signer_address(transaction.version)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(&json.sender, origin);

        let recipient = transaction.payload_recipient_address().unwrap();
        let addr_len = recipient.len();
        let address = core::str::from_utf8(&recipient[0..addr_len]).unwrap();
        assert_eq!(&json.recipient, address);
    }
}
