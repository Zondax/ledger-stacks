use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{be_u32, be_u64, le_u8},
};

use crate::parser::parser_common::{
    u8_with_limits, AssetInfo, AssetInfoId, AssetName, ClarityName, ContractName, Hash160,
    ParserError, StacksAddress, StacksString, MAX_STACKS_STRING_LEN, MAX_STRING_LEN,
    NUM_SUPPORTED_POST_CONDITIONS,
};

use crate::parser::value::{Value, BIG_INT_SIZE};

pub const MAX_NUM_ARGS: u32 = 10;

#[repr(u8)]
#[derive(Debug, Clone, PartialEq)]
pub enum TokenTranferType {
    Stx = 0x00,
    Fungible,
    NonFungible,
}

impl TokenTranferType {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            0 => Ok(Self::Stx),
            1 => Ok(Self::Fungible),
            2 => Ok(Self::NonFungible),
            _ => Err(ParserError::parser_invalid_token_transfer_type),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub enum TokenTransferPayload<'a> {
    StxToken(StacksAddress<'a>, u64),
    FungibleToken(AssetInfo<'a>, StacksAddress<'a>, u64),
    NonFungibleToken(AssetInfo<'a>, ClarityName<'a>, StacksAddress<'a>),
}

impl<'a> TokenTransferPayload<'a> {
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let res = match TokenTranferType::from_u8(id.1)? {
            TokenTranferType::Stx => {
                let values = permutation((StacksAddress::from_bytes, be_u64))(id.0)?;
                (values.0, Self::StxToken((values.1).0, (values.1).1))
            }
            TokenTranferType::Fungible => {
                let values =
                    permutation((AssetInfo::from_bytes, StacksAddress::from_bytes, be_u64))(id.0)?;
                (
                    values.0,
                    Self::FungibleToken((values.1).0, (values.1).1, (values.1).2),
                )
            }
            TokenTranferType::NonFungible => {
                let values = permutation((
                    AssetInfo::from_bytes,
                    ClarityName::from_bytes,
                    StacksAddress::from_bytes,
                ))(id.0)?;
                (
                    values.0,
                    Self::NonFungibleToken((values.1).0, (values.1).1, (values.1).2),
                )
            }
        };
        Ok(res)
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
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (leftover, (name, code_body)) =
            permutation((ContractName::from_bytes, StacksString::from_bytes))(bytes)?;
        Ok((leftover, Self { name, code_body }))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPayloadId {
    TokenTransfer = 0,
    SmartContract = 1,
    ContractCall = 2,
}

impl TransactionPayloadId {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            0 => Ok(Self::TokenTransfer),
            1 => Ok(Self::SmartContract),
            2 => Ok(Self::ContractCall),
            _ => Err(ParserError::parser_invalid_transaction_payload),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub enum TransactionPayload<'a> {
    TokenTransfer(TokenTransferPayload<'a>),
    ContractCall(TransactionContractCall<'a>),
    SmartContract(TransactionSmartContract<'a>),
}

impl<'a> TransactionPayload<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let res = match TransactionPayloadId::from_u8(id.1)? {
            TransactionPayloadId::TokenTransfer => {
                let token = TokenTransferPayload::from_bytes(id.0)?;
                (token.0, Self::TokenTransfer(token.1))
            }
            TransactionPayloadId::ContractCall => {
                let call = TransactionContractCall::from_bytes(id.0)?;
                (call.0, Self::ContractCall(call.1))
            }
            TransactionPayloadId::SmartContract => {
                let contract = TransactionSmartContract::from_bytes(id.0)?;
                (contract.0, Self::SmartContract(contract.1))
            }
        };
        Ok(res)
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
        let hash160 = Hash160(hash.as_ref());
        let contract_name = ContractName("contract-name".as_bytes().as_ref());
        let asset_name = ClarityName("hello-asset".as_bytes().as_ref());
        let asset_info = AssetInfo {
            address: StacksAddress(1, Hash160([1u8; 20].as_ref())),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        };
        let token = TokenTransferPayload::StxToken(StacksAddress(1, hash160.clone()), 123);
        let tt_stx = TransactionPayload::TokenTransfer(token);

        let bytes: Vec<u8> = vec![
            0, 0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 123,
        ];

        let mut parsed = TransactionPayload::from_bytes(&bytes).unwrap().1;
        assert_eq!(tt_stx, parsed);
        let token =
            TokenTransferPayload::FungibleToken(asset_info, StacksAddress(2, hash160.clone()), 123);
        let tt_fungible = TransactionPayload::TokenTransfer(token);

        let bytes_fungible: Vec<u8> = vec![
            0, 1, // asset_info stack address
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, // asset-info contract name
            13, 99, 111, 110, 116, 114, 97, 99, 116, 45, 110, 97, 109, 101,
            // asset-info - asset_name
            11, 104, 101, 108, 108, 111, 45, 97, 115, 115, 101, 116, // stacks-address
            2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 123,
        ];
        parsed = TransactionPayload::from_bytes(&bytes_fungible).unwrap().1;
        assert_eq!(tt_fungible, parsed);

        let token = TokenTransferPayload::NonFungibleToken(
            asset_info,
            asset_name,
            StacksAddress(2, hash160.clone()),
        );
        let tt_nonfungible = TransactionPayload::TokenTransfer(token);

        let bytes_nonfungible: Vec<u8> = vec![
            0, 2, // asset_info stack address
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, // asset-info contract name
            13, 99, 111, 110, 116, 114, 97, 99, 116, 45, 110, 97, 109, 101,
            // asset-info - asset_name
            11, 104, 101, 108, 108, 111, 45, 97, 115, 115, 101, 116, // asset-name2
            11, 104, 101, 108, 108, 111, 45, 97, 115, 115, 101, 116, // stacks-address
            2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255,
        ];
        parsed = TransactionPayload::from_bytes(&bytes_nonfungible)
            .unwrap()
            .1;

        assert_eq!(tt_nonfungible, parsed);
    }
}
