mod arguments;
mod contract_call;
mod smart_contract;
mod token_transfer;
mod versioned_contract;

use nom::number::complete::le_u8;

use self::{
    contract_call::{TransactionContractCall, CONTRACT_CALL_BASE_ITEMS},
    smart_contract::TransactionSmartContract,
    token_transfer::StxTokenTransfer,
    versioned_contract::VersionedSmartContract,
};

use super::{ContractName, FromBytes, C32_ENCODED_ADDRS_LENGTH};
use crate::{bolos::c_zemu_log_stack, parser::error::ParserError};

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionPayloadId {
    TokenTransfer = 0,
    SmartContract = 1,
    ContractCall = 2,
    VersionedSmartContract = 6,
}

impl TransactionPayloadId {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            0 => Ok(Self::TokenTransfer),
            1 => Ok(Self::SmartContract),
            2 => Ok(Self::ContractCall),
            6 => Ok(Self::VersionedSmartContract),
            _ => Err(ParserError::InvalidTransactionPayload),
        }
    }
}

// Define tuple structs for each variant
#[repr(C)]
struct TokenTransferVariant<'a>(TransactionPayloadId, StxTokenTransfer<'a>);

#[repr(C)]
struct SmartContractVariant<'a>(TransactionPayloadId, TransactionSmartContract<'a>);

#[repr(C)]
struct ContractCallVariant<'a>(TransactionPayloadId, TransactionContractCall<'a>);

#[repr(C)]
struct VersionedSmartContractVariant<'a>(TransactionPayloadId, VersionedSmartContract<'a>);

#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionPayload<'a> {
    TokenTransfer(StxTokenTransfer<'a>),
    SmartContract(TransactionSmartContract<'a>),
    ContractCall(TransactionContractCall<'a>),
    VersionedSmartContract(VersionedSmartContract<'a>),
}

impl<'b> FromBytes<'b> for TransactionPayload<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;
        c_zemu_log_stack(b"TransactionPayload::from_bytes_into\x00");

        if input.is_empty() {
            return Err(nom::Err::Error(ParserError::UnexpectedBufferEnd));
        }

        // Extract the payload type ID
        let (rem, payload_id_byte) = le_u8(input)?;

        // Convert to enum
        let payload_id = TransactionPayloadId::from_u8(payload_id_byte)?;
        #[cfg(test)]
        std::println!("Payload ID: {:?}", payload_id);

        // Process based on payload type
        match payload_id {
            TransactionPayloadId::TokenTransfer => {
                // Cast output pointer to TokenTransferVariant
                let out_ptr = out.as_mut_ptr() as *mut TokenTransferVariant;

                // Get a reference to the uninitialized StxTokenTransfer field
                let token_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).1).cast() };

                // Parse the StxTokenTransfer
                let rem = StxTokenTransfer::from_bytes_into(rem, token_uninit)?;

                // Set the tag (payload ID)
                unsafe {
                    addr_of_mut!((*out_ptr).0).write(TransactionPayloadId::TokenTransfer);
                }

                Ok(rem)
            }
            TransactionPayloadId::SmartContract => {
                // Cast output pointer to SmartContractVariant
                let out_ptr = out.as_mut_ptr() as *mut SmartContractVariant;

                // Get a reference to the uninitialized TransactionSmartContract field
                let contract_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).1).cast() };

                // Parse the TransactionSmartContract
                let rem = TransactionSmartContract::from_bytes_into(rem, contract_uninit)?;

                // Set the tag (payload ID)
                unsafe {
                    addr_of_mut!((*out_ptr).0).write(TransactionPayloadId::SmartContract);
                }

                Ok(rem)
            }
            TransactionPayloadId::ContractCall => {
                // Cast output pointer to ContractCallVariant
                let out_ptr = out.as_mut_ptr() as *mut ContractCallVariant;

                // Get a reference to the uninitialized TransactionContractCall field
                let call_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).1).cast() };

                // Parse the TransactionContractCall
                let rem = TransactionContractCall::from_bytes_into(rem, call_uninit)?;

                // Set the tag (payload ID)
                unsafe {
                    addr_of_mut!((*out_ptr).0).write(TransactionPayloadId::ContractCall);
                }

                Ok(rem)
            }
            TransactionPayloadId::VersionedSmartContract => {
                // Cast output pointer to VersionedSmartContractVariant
                let out_ptr = out.as_mut_ptr() as *mut VersionedSmartContractVariant;

                // Get a reference to the uninitialized VersionedSmartContract field
                let versioned_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).1).cast() };

                // Parse the VersionedSmartContract
                let rem = VersionedSmartContract::from_bytes_into(rem, versioned_uninit)?;

                // Set the tag (payload ID)
                unsafe {
                    addr_of_mut!((*out_ptr).0).write(TransactionPayloadId::VersionedSmartContract);
                }

                Ok(rem)
            }
        }
    }
}

impl<'a> TransactionPayload<'a> {
    pub fn is_token_transfer_payload(&self) -> bool {
        matches!(self, &Self::TokenTransfer(_))
    }

    pub fn is_smart_contract_payload(&self) -> bool {
        matches!(self, &Self::SmartContract(_))
    }
    pub fn is_contract_call_payload(&self) -> bool {
        matches!(self, &Self::ContractCall(_))
    }

    pub fn is_contract_deploy_payload(&self) -> bool {
        matches!(self, &Self::VersionedSmartContract(_))
    }

    pub fn contract_name(&'a self) -> Option<ContractName<'a>> {
        match self {
            Self::SmartContract(contract) => contract.contract_name().ok(),
            Self::ContractCall(contract) => contract.contract_name().ok(),
            Self::VersionedSmartContract(contract) => contract.contract_name().ok(),
            _ => None,
        }
    }

    pub fn function_name(&self) -> Option<&[u8]> {
        match self {
            Self::ContractCall(ref contract) => contract.function_name().ok(),
            _ => None,
        }
    }

    pub fn num_args(&self) -> Option<u32> {
        match self {
            Self::ContractCall(ref contract) => contract.num_args().ok(),
            _ => None,
        }
    }

    pub fn amount(&self) -> Option<u64> {
        match self {
            Self::TokenTransfer(ref token) => token.amount().ok(),
            _ => None,
        }
    }

    pub fn memo(&self) -> Option<&[u8]> {
        match self {
            Self::TokenTransfer(ref token) => Some(token.memo()),
            _ => None,
        }
    }

    pub fn recipient_address(&self) -> Option<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>> {
        match self {
            Self::TokenTransfer(ref token) => token.encoded_address().ok(),
            _ => None,
        }
    }
    pub fn contract_address(&self) -> Option<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>> {
        match self {
            Self::ContractCall(ref call) => call.contract_address().ok(),
            _ => None,
        }
    }

    pub fn num_items(&self) -> u8 {
        match self {
            Self::TokenTransfer(_) => 3,
            Self::SmartContract(_) | Self::VersionedSmartContract(_) => 1,
            Self::ContractCall(ref call) => call.num_items().unwrap_or(CONTRACT_CALL_BASE_ITEMS),
        }
    }

    pub fn get_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
        total_items: u8,
    ) -> Result<u8, ParserError> {
        let idx = self.num_items() - (total_items - display_idx);
        match self {
            Self::TokenTransfer(ref token) => {
                token.get_token_transfer_items(idx, out_key, out_value, page_idx)
            }
            Self::SmartContract(ref contract) => {
                contract.get_contract_items(idx, out_key, out_value, page_idx)
            }
            Self::ContractCall(ref call) => {
                call.get_contract_call_items(idx, out_key, out_value, page_idx)
            }
            Self::VersionedSmartContract(ref deploy) => {
                deploy.get_contract_items(idx, out_key, out_value, page_idx)
            }
        }
    }

    pub fn raw_payload(&self) -> &'a [u8] {
        match self {
            Self::TokenTransfer(token) => token.raw_data(),
            Self::SmartContract(contract) => contract.raw_data(),
            Self::ContractCall(call) => call.raw_data(),
            Self::VersionedSmartContract(deploy) => deploy.raw_data(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::prelude::v1::*;

    #[test]
    fn test_transaction_payload_tokens() {
        let bytes: Vec<u8> = vec![
            0, 5, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let parsed = TransactionPayload::from_bytes(&bytes).unwrap().1;
        assert_eq!(parsed.amount(), Some(123));
    }
}
