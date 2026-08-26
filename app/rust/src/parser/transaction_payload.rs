mod arguments;
mod contract_call;
mod smart_contract;
mod token_transfer;
mod versioned_contract;

use nom::number::complete::le_u8;

use self::{
    contract_call::TransactionContractCallWrapper,
    smart_contract::TransactionSmartContract,
    token_transfer::StxTokenTransfer,
    versioned_contract::VersionedSmartContract,
};

use super::{ContractName, C32_ENCODED_ADDRS_LENGTH};

// Re-exported so `Transaction` can budget its display items against the same constant the
// contract-call renderer uses.
pub use self::contract_call::CONTRACT_CALL_BASE_ITEMS;
#[cfg(test)]
pub use self::contract_call::{MAX_ARG_DISPLAY_ITEMS, MAX_VALUE_TEXT};

/// How this transaction's items are laid out.
///
/// Both decisions belong to the transaction, not the payload: one needs the post-conditions, the
/// other needs the whole item budget. They are settled once per `get_item`/`num_items` and passed
/// down together, so the count and the rendering cannot disagree about which layout is in use.
#[derive(Clone, Copy)]
pub struct DisplayMode {
    /// Collapse a recognised SIP-10 transfer to Amount / From / To / Memo.
    pub hide_sip10_details: bool,
    /// Show contract-call arguments one display item per leaf, rather than one per argument.
    pub flatten_args: bool,
}
use crate::parser::error::ParserError;

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

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionPayload<'a> {
    TokenTransfer(StxTokenTransfer<'a>),
    SmartContract(TransactionSmartContract<'a>),
    ContractCall(TransactionContractCallWrapper<'a>),
    VersionedSmartContract(VersionedSmartContract<'a>),
}

impl<'a> TransactionPayload<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let res = match TransactionPayloadId::from_u8(id.1)? {
            TransactionPayloadId::TokenTransfer => {
                let token = StxTokenTransfer::from_bytes(id.0)?;
                (token.0, Self::TokenTransfer(token.1))
            }
            TransactionPayloadId::SmartContract => {
                let contract = TransactionSmartContract::from_bytes(id.0)?;
                (contract.0, Self::SmartContract(contract.1))
            }
            TransactionPayloadId::ContractCall => {
                let call = TransactionContractCallWrapper::from_bytes(id.0)?;
                (call.0, Self::ContractCall(call.1))
            }
            TransactionPayloadId::VersionedSmartContract => {
                let call = VersionedSmartContract::from_bytes(id.0)?;
                (call.0, Self::VersionedSmartContract(call.1))
            }
        };
        Ok(res)
    }

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

    /// An error here means the items do not fit the u8 display index, and it must propagate:
    /// the transaction is refused. This used to fall back to CONTRACT_CALL_BASE_ITEMS, which
    /// made a call with 253 or more arguments review as six items -- origin, nonce, fee and the
    /// three base items -- with every argument silently absent and no blind-signing warning.
    pub fn num_items(&self, mode: DisplayMode) -> Result<u8, ParserError> {
        match self {
            Self::TokenTransfer(_) => Ok(3),
            Self::SmartContract(_) | Self::VersionedSmartContract(_) => Ok(1),
            Self::ContractCall(ref call) => call.num_items(mode),
        }
    }

    /// Whether this payload contains data the device will sign but cannot display in full.
    ///
    /// A contract deploy shows only the contract *name* -- the Clarity source code it commits to
    /// is never rendered -- so it is always blind. A token transfer renders every one of its three
    /// items. A contract call depends on its argument types.
    pub fn requires_blindsign(&self) -> Result<bool, ParserError> {
        match self {
            Self::TokenTransfer(_) => Ok(false),
            Self::SmartContract(_) | Self::VersionedSmartContract(_) => Ok(true),
            Self::ContractCall(ref call) => call.requires_blindsign(),
        }
    }

    pub fn get_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
        total_items: u8,
        mode: DisplayMode,
    ) -> Result<u8, ParserError> {
        let idx = self.num_items(mode)? - (total_items - display_idx);
        match self {
            Self::TokenTransfer(ref token) => {
                token.get_token_transfer_items(idx, out_key, out_value, page_idx)
            }
            Self::SmartContract(ref contract) => {
                contract.get_contract_items(idx, out_key, out_value, page_idx)
            }
            Self::ContractCall(ref call) => {
                call.get_contract_call_items(idx, out_key, out_value, page_idx, mode)
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
