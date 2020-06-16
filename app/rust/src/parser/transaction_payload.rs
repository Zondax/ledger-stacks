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
pub enum TokeTransferPayload<'a> {
    StxToken(StacksAddress<'a>, u64),
    FungibleToken(AssetInfo<'a>, StacksAddress<'a>, u64),
    NonFungibleToken(AssetInfo<'a>, AssetName<'a>, StacksAddress<'a>),
}

impl<'a> TokeTransferPayload<'a> {
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
                    AssetName::from_bytes,
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
#[derive(Clone, Copy)]
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
pub enum TransactionPayload<'a> {
    TokenTransfer(TokeTransferPayload<'a>),
    ContractCall(TransactionContractCall<'a>),
    SmartContract(TransactionSmartContract<'a>),
}

impl<'a> TransactionPayload<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let res = match TransactionPayloadId::from_u8(id.1)? {
            TransactionPayloadId::TokenTransfer => {
                let token = TokeTransferPayload::from_bytes(id.0)?;
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
