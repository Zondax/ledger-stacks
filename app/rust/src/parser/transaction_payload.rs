use core::fmt::{self, Write};
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{be_u32, be_u64, le_u8},
};

use arrayvec::ArrayVec;

use crate::parser::parser_common::{
    u8_with_limits, AssetInfo, AssetInfoId, AssetName, ClarityName, ContractName, Hash160,
    ParserError, PrincipalData, StacksAddress, StacksString, StandardPrincipal, TokenTransferMemo,
    MAX_STACKS_STRING_LEN, MAX_STRING_LEN, NUM_SUPPORTED_POST_CONDITIONS,
};

use crate::parser::ffi::fp_uint64_to_str;
use crate::parser::value::{Value, BIG_INT_SIZE};
use crate::zxformat;

pub const MAX_NUM_ARGS: u32 = 10;

const STX_DECIMALS: u8 = 6;

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum TokenTranferPrincipal {
    Standard = 0x05,
    Contract = 0x06,
}

impl TokenTranferPrincipal {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            5 => Ok(Self::Standard),
            6 => Ok(Self::Contract),
            _ => Err(ParserError::parser_invalid_token_transfer_principal),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct StxTokenTransfer<'a> {
    pub principal: PrincipalData<'a>,
    pub amount: u64,
    pub memo: TokenTransferMemo<'a>,
}

impl<'a> StxTokenTransfer<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let principal = match TokenTranferPrincipal::from_u8(id.1)? {
            TokenTranferPrincipal::Standard => PrincipalData::standard_from_bytes(id.0)?,
            TokenTranferPrincipal::Contract => PrincipalData::contract_principal_from_bytes(id.0)?,
        };
        let amount = be_u64(principal.0)?;
        let memo = TokenTransferMemo::from_bytes(amount.0)?;
        Ok((
            memo.0,
            Self {
                principal: principal.1,
                amount: amount.1,
                memo: memo.1,
            },
        ))
    }

    pub fn memo(&self) -> &[u8] {
        self.memo.0
    }

    pub fn raw_address(&self) -> &[u8] {
        self.principal.raw_address()
    }

    pub fn encoded_address(&self) -> Result<ArrayVec<[u8; 64]>, ParserError> {
        self.principal.encoded_address()
    }

    pub fn amount_stx(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        let mut output: ArrayVec<[_; zxformat::MAX_STR_BUFF_LEN]> = ArrayVec::new();
        let len = if cfg!(test) {
            zxformat::fpu64_to_str(output.as_mut(), self.amount, STX_DECIMALS)? as usize
        } else {
            unsafe {
                fp_uint64_to_str(
                    output.as_mut_ptr() as _,
                    zxformat::MAX_STR_BUFF_LEN as u16,
                    self.amount,
                    STX_DECIMALS,
                ) as usize
            }
        };
        unsafe {
            output.set_len(len);
        }
        Ok(output)
    }

    fn get_token_transfer_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        match display_idx {
            // Fomatting the amount in stx
            0 => {
                writer_key
                    .write_str("Amount")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let amount = self.amount_stx()?;
                zxformat::pageString(out_value, amount.as_ref(), page_idx)
            }
            // Recipient address
            1 => {
                writer_key
                    .write_str("To")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let recipient = self.encoded_address()?;
                zxformat::pageString(out_value, recipient.as_ref(), page_idx)
            }
            2 => {
                writer_key
                    .write_str("Memo")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                zxformat::pageString(out_value, self.memo(), page_idx)
            }
            _ => unimplemented!(),
        }
    }
}

/// A transaction that calls into a smart contract
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionContractCall<'a> {
    address: StacksAddress<'a>,
    contract_name: ContractName<'a>,
    function_name: ClarityName<'a>,
    function_args: Arguments<'a>,
}

impl<'a> TransactionContractCall<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (leftover, (address, contract_name, function_name, function_args)) = permutation((
            StacksAddress::from_bytes,
            ContractName::from_bytes,
            ClarityName::from_bytes,
            Arguments::from_bytes,
        ))(bytes)?;
        Ok((
            leftover,
            Self {
                address,
                contract_name,
                function_name,
                function_args,
            },
        ))
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct Arguments<'a> {
    len: usize,
    args: [Option<Value<'a>>; MAX_NUM_ARGS as usize],
}

impl<'a> Arguments<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let len = be_u32(bytes)?;
        let mut arguments: [Option<Value<'a>>; MAX_NUM_ARGS as _] = [None; MAX_NUM_ARGS as _];
        let mut iter = iterator(len.0, Value::from_bytes);
        iter.take(len.1 as _)
            .enumerate()
            .zip(arguments.iter_mut())
            .for_each(|i| {
                *i.1 = Some((i.0).1);
            });
        let res = iter.finish()?;
        Ok((
            res.0,
            Self {
                len: len.1 as usize,
                args: arguments,
            },
        ))
    }
}

/// A transaction that instantiates a smart contract
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionSmartContract<'a> {
    pub name: ContractName<'a>,
    pub code_body: StacksString<'a>,
}

impl<'a> TransactionSmartContract<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (leftover, (name, code_body)) =
            permutation((ContractName::from_bytes, StacksString::from_bytes))(bytes)?;
        Ok((leftover, Self { name, code_body }))
    }

    fn get_contract_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        match display_idx {
            // Fomatting the amount in stx
            0 => {
                writer_key
                    .write_str("Contract Name")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                // TODO: chck if contract name is encoded in somehow
                zxformat::pageString(out_value, self.name.0, page_idx)
            }
            _ => unimplemented!(),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPayloadId {
    TokenTransfer = 0,
    SmartContract = 1,
}

impl TransactionPayloadId {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            0 => Ok(Self::TokenTransfer),
            1 => Ok(Self::SmartContract),
            _ => Err(ParserError::parser_invalid_transaction_payload),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionPayload<'a> {
    TokenTransfer(StxTokenTransfer<'a>),
    SmartContract(TransactionSmartContract<'a>),
}

impl<'a> TransactionPayload<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let res = match TransactionPayloadId::from_u8(id.1)? {
            TransactionPayloadId::TokenTransfer => {
                let token = StxTokenTransfer::from_bytes(id.0)?;
                (token.0, Self::TokenTransfer(token.1))
            }
            _ => unimplemented!(),
        };
        Ok(res)
    }

    #[inline(never)]
    pub fn is_token_transfer_payload(&self) -> bool {
        match *self {
            Self::TokenTransfer(_) => true,
            _ => false,
        }
    }

    pub fn amount(&self) -> Option<u64> {
        match *self {
            Self::TokenTransfer(ref token) => Some(token.amount),
            _ => unimplemented!(),
        }
    }

    pub fn memo(&self) -> Option<&[u8]> {
        match *self {
            Self::TokenTransfer(ref token) => Some(token.memo.0),
            _ => None,
        }
    }

    pub fn recipient_address(&self) -> Option<arrayvec::ArrayVec<[u8; 64]>> {
        match *self {
            Self::TokenTransfer(ref token) => token.encoded_address().ok(),
            _ => None,
        }
    }

    pub fn num_items(&self) -> u8 {
        match *self {
            Self::TokenTransfer(_) => 3,
            Self::SmartContract(_) => 1,
        }
    }

    pub fn get_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let idx = display_idx % self.num_items();
        match *self {
            Self::TokenTransfer(ref token) => {
                token.get_token_transfer_items(idx, out_key, out_value, page_idx)
            }
            Self::SmartContract(ref contract) => {
                contract.get_contract_items(idx, out_key, out_value, page_idx)
            }
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
    fn test_transaction_payload_tokens() {
        let hash = [0xff; 20];
        let memo = [0x00; 34];
        let token = StxTokenTransfer {
            principal: PrincipalData::Standard(StandardPrincipal(1, hash.as_ref())),
            amount: 123,
            memo: TokenTransferMemo(memo.as_ref()),
        };
        let tt_stx = TransactionPayload::TokenTransfer(token);

        let bytes: Vec<u8> = vec![
            0, 5, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let parsed = TransactionPayload::from_bytes(&bytes).unwrap().1;
        assert_eq!(tt_stx, parsed);
    }
}
