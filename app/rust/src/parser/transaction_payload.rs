use core::fmt::Write;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{flat_map, map},
    number::complete::{be_u32, be_u64, be_u8, le_u8},
    sequence::tuple,
};

use arrayvec::ArrayVec;
use numtoa::NumToA;

use super::{
    utils::ApduPanic, ClarityName, ContractName, PrincipalData, StacksAddress,
    C32_ENCODED_ADDRS_LENGTH, HASH160_LEN, TX_DEPTH_LIMIT,
};
use crate::parser::error::ParserError;

use crate::parser::c32;

use super::value::{Value, ValueId};
use crate::{check_canary, is_expert_mode, zxformat};

// The number of contract call arguments we can handle.
// this can be adjusted, but keep in mind that higher values could
// hit stack overflows issues.
pub const MAX_NUM_ARGS: u32 = 10;

// The items in contract_call transactions are
// contract_address, contract_name and function_name
pub const CONTRACT_CALL_BASE_ITEMS: u8 = 3;

pub const MAX_STRING_ASCII_TO_SHOW: usize = 60;

#[repr(u8)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum TokenTranferPrincipal {
    Standard = 0x05,
    Contract = 0x06,
}

impl TokenTranferPrincipal {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            5 => Ok(Self::Standard),
            6 => Ok(Self::Contract),
            _ => Err(ParserError::InvalidTokenTransferPrincipal),
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct StxTokenTransfer<'a>(&'a [u8]);

impl<'a> StxTokenTransfer<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let (raw, _) = match TokenTranferPrincipal::from_u8(id.1)? {
            TokenTranferPrincipal::Standard => PrincipalData::standard_from_bytes(id.0)?,
            TokenTranferPrincipal::Contract => PrincipalData::contract_principal_from_bytes(id.0)?,
        };
        // Besides principal we take 34-bytes being the MEMO message + 8-bytes amount of stx
        let len = bytes.len() - raw.len() + 34 + 8;
        let (raw, data) = take(len)(bytes)?;
        Ok((raw, Self(data)))
    }

    pub fn memo(&self) -> &[u8] {
        let at = self.0.len() - 34;
        // safe to unwrap as parser checked for proper len
        self.0.get(at..).apdu_unwrap()
    }

    pub fn amount(&self) -> Result<u64, ParserError> {
        let at = self.0.len() - 34 - 8;
        let amount = self.0.get(at..).ok_or(ParserError::NoData)?;
        be_u64::<_, ParserError>(amount)
            .map(|res| res.1)
            .map_err(|_| ParserError::UnexpectedBufferEnd)
    }

    pub fn raw_address(&self) -> &[u8] {
        // Skips the principal-id and hash_mode
        // is valid as this was check by the parser
        // safe to unwrap as this was checked at parsing
        self.0.get(2..22).apdu_unwrap()
    }

    pub fn encoded_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        // Skips the principal-id at [0] and uses hash_mode and the follow 20-bytes
        let version = self.0.get(1).ok_or(ParserError::NoData)?;
        c32::c32_address(
            *version,
            self.0.get(2..22).ok_or(ParserError::InvalidAddress)?,
        )
    }

    pub fn amount_stx(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
        let amount = self.amount()?;
        let len = zxformat::u64_to_str(output.as_mut(), amount)? as usize;
        unsafe {
            output.set_len(len);
        }
        check_canary!();
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
                    .write_str("Amount uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let amount = self.amount_stx()?;
                check_canary!();
                zxformat::pageString(out_value, amount.as_ref(), page_idx)
            }
            // Recipient address
            1 => {
                writer_key
                    .write_str("To")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let recipient = self.encoded_address()?;
                check_canary!();
                zxformat::pageString(out_value, recipient.as_ref(), page_idx)
            }
            2 => {
                writer_key
                    .write_str("Memo")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                zxformat::pageString(out_value, self.memo(), page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Arguments<'a>(&'a [u8]);

impl<'a> Arguments<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        check_canary!();

        let (_, num_args) = be_u32::<_, ParserError>(bytes)?;

        if num_args > MAX_NUM_ARGS && !is_expert_mode() {
            return Err(ParserError::InvalidTransactionPayload.into());
        }
        let (raw, args) = take(bytes.len())(bytes)?;

        // take all bytes as there must not be more data after the arguments
        // returning an empty remain data. NOTE: we use take(bytes.len()), to offset
        // the remainder bytes as it is used to set the tx.remainder, which is use
        // to calculate the last_tx_block during the transaction signing process
        Ok((raw, Self(args)))
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        be_u32::<_, ParserError>(self.0)
            .map(|res| res.1)
            .map_err(|_| ParserError::UnexpectedError)
    }

    pub fn argument_at(&self, at: usize) -> Result<Value<'a>, ParserError> {
        check_canary!();

        let mut idx = 0;
        let num_args = self.num_args()?;

        // skip the first 4-bytes
        let mut leftover = &self.0[4..];

        while idx < num_args as usize {
            let (bytes, value) = Value::from_bytes::<TX_DEPTH_LIMIT>(leftover)
                .map_err(|_| ParserError::InvalidArgumentId)?;

            leftover = bytes;
            if idx == at {
                return Ok(value);
            }
            idx += 1;
        }
        Err(ParserError::DisplayIdxOutOfRange)
    }
}

/// A transaction that calls into a smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionContractCall<'a>(&'a [u8]);

impl<'a> TransactionContractCall<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, _) = StacksAddress::from_bytes(bytes)?;
        // get contract name and function name.
        let (raw2, _) = tuple((ContractName::from_bytes, ClarityName::from_bytes))(raw)?;
        let (leftover, _) = Arguments::from_bytes(raw2)?;
        let len = bytes.len() - leftover.len();
        let (_, data) = take(len)(bytes)?;
        check_canary!();
        Ok((leftover, Self(data)))
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        let at = HASH160_LEN + 1;
        ContractName::from_bytes(&self.0[at..])
            .map(|(_, name)| name)
            .map_err(|e| e.into())
    }

    pub fn function_name(&self) -> Result<&[u8], ParserError> {
        ContractName::from_bytes(&self.0[(HASH160_LEN + 1)..])
            .and_then(|b| ClarityName::from_bytes(b.0))
            .map(|res| (res.1).0)
            .map_err(|_| ParserError::UnexpectedError)
    }

    pub fn function_args(&self) -> Result<Arguments<'a>, ParserError> {
        ContractName::from_bytes(&self.0[(HASH160_LEN + 1)..])
            .and_then(|b| ClarityName::from_bytes(b.0))
            .and_then(|c| Arguments::from_bytes(c.0))
            .map(|res| res.1)
            .map_err(|_| ParserError::InvalidArgumentId)
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        self.function_args().and_then(|args| args.num_args())
    }

    #[inline(never)]
    pub fn contract_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let version = self.0[0];
        c32::c32_address(version, &self.0[1..21])
    }

    // change label if it is a stacking contract call
    fn label_stacking_value(&self, key: &mut [u8]) -> Result<(), ParserError> {
        let addr = self.contract_address()?;
        let addr = addr.as_ref();
        let contract_name = self.contract_name()?;
        if (addr == "SP000000000000000000002Q6VF78".as_bytes()
            || addr == "ST000000000000000000002AMW42H".as_bytes())
            && contract_name.name() == "pox".as_bytes()
        {
            let name = self.function_name()?;
            if name == "stack-stx".as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("stacked uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            } else if name == "delegate-stx".as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("delegated uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            }
        }
        Ok(())
    }

    fn get_contract_call_args(
        &'a self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx < CONTRACT_CALL_BASE_ITEMS {
            return Err(ParserError::DisplayIdxOutOfRange);
        }
        let arg_num = display_idx - CONTRACT_CALL_BASE_ITEMS;

        let args = self.function_args()?;

        let value = args.argument_at(arg_num as _)?;

        {
            let mut writer_key = zxformat::Writer::new(out_key);
            let mut arg_num_buff = [0u8; 3];
            let arg_num_str = arg_num.numtoa_str(10, &mut arg_num_buff);

            writer_key
                .write_str("arg")
                .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            writer_key
                .write_str(arg_num_str)
                .map_err(|_| ParserError::UnexpectedBufferEnd)?;
        }

        // return the value content including the valueID
        let payload = value.payload();

        match value.value_id() {
            ValueId::Int => {
                let value = value.int().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 39];

                zxformat::pageString(
                    out_value,
                    value.numtoa_str(10, &mut buff).as_bytes(),
                    page_idx,
                )
            }
            ValueId::UInt => {
                let value = value.uint().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 39];

                if arg_num == 0 {
                    self.label_stacking_value(out_key)?;
                }

                zxformat::pageString(
                    out_value,
                    value.numtoa_str(10, &mut buff).as_bytes(),
                    page_idx,
                )
            }
            ValueId::BoolTrue => {
                zxformat::pageString(out_value, "is bool: true".as_bytes(), page_idx)
            }
            ValueId::BoolFalse => {
                zxformat::pageString(out_value, "is bool: false".as_bytes(), page_idx)
            }
            ValueId::OptionalNone => {
                zxformat::pageString(out_value, "is Option: None".as_bytes(), page_idx)
            }
            ValueId::OptionalSome => {
                zxformat::pageString(out_value, "is Option: Some".as_bytes(), page_idx)
            }
            ValueId::ResponseOk => {
                zxformat::pageString(out_value, "is Result: Ok".as_bytes(), page_idx)
            }
            ValueId::ResponseErr => {
                zxformat::pageString(out_value, "is Result: Err".as_bytes(), page_idx)
            }
            ValueId::StandardPrincipal => {
                let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                let address = principal.encoded_address()?;
                zxformat::pageString(out_value, &address[0..address.len()], page_idx)
            }
            ValueId::ContractPrincipal => {
                // holds principal_encoded address + '.' + contract_name
                let mut data = [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];

                let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                let address = principal.encoded_address()?;

                // should not fail as this was parsed in previous step
                let contract_name = principal.contract_name().apdu_unwrap();

                data.get_mut(..address.len())
                    .apdu_unwrap()
                    .copy_from_slice(&address[0..address.len()]);

                data[address.len()] = '.' as u8;
                let len = address.len() + 1;

                // wont panic as we reserved enough space.
                data.get_mut(len..len + contract_name.len())
                    .apdu_unwrap()
                    .copy_from_slice(contract_name.name());

                zxformat::pageString(out_value, &data[0..len + contract_name.len()], page_idx)
            }
            ValueId::Buffer => zxformat::pageString(out_value, "is Buffer".as_bytes(), page_idx),
            ValueId::List => zxformat::pageString(out_value, "is List".as_bytes(), page_idx),
            ValueId::Tuple => zxformat::pageString(out_value, "is Tuple".as_bytes(), page_idx),
            ValueId::StringAscii => {
                // 4 bytes encode the length of the string
                let len = if payload.len() - 4 > MAX_STRING_ASCII_TO_SHOW {
                    MAX_STRING_ASCII_TO_SHOW
                } else {
                    payload.len()
                };
                zxformat::pageString(
                    out_value,
                    &payload[4..len], // omit the first 4-bytes as they are the string length
                    page_idx,
                )
            }

            ValueId::StringUtf8 => {
                zxformat::pageString(out_value, "is StringUtf8".as_bytes(), page_idx)
            }
        }
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        // contract-address, contract-name, function-name
        // + the number of arguments
        let num_args = self.num_args()? as u8;
        num_args
            .checked_add(CONTRACT_CALL_BASE_ITEMS)
            .ok_or(ParserError::ValueOutOfRange)
    }

    fn get_base_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx > CONTRACT_CALL_BASE_ITEMS {
            return Err(ParserError::DisplayIdxOutOfRange);
        }
        let mut writer_key = zxformat::Writer::new(out_key);
        match display_idx {
            // Contract-address
            0 => {
                writer_key
                    .write_str("Contract address")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let address = self.contract_address()?;
                check_canary!();
                zxformat::pageString(out_value, address.as_ref(), page_idx)
            }
            // Contract.name
            1 => {
                writer_key
                    .write_str("Contract name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.contract_name()?;
                check_canary!();
                zxformat::pageString(out_value, name.name(), page_idx)
            }
            // Function-name
            2 => {
                writer_key
                    .write_str("Function name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.function_name()?;
                check_canary!();
                zxformat::pageString(out_value, name, page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    fn get_contract_call_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // display_idx was already normalize
        if display_idx < CONTRACT_CALL_BASE_ITEMS {
            self.get_base_items(display_idx, out_key, out_value, page_idx)
        } else {
            self.get_contract_call_args(display_idx, out_key, out_value, page_idx)
        }
    }
}

/// A transaction that deploys a versioned smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct VersionedSmartContract<'a>(&'a [u8]);

impl<'a> VersionedSmartContract<'a> {
    #[inline(never)]
    fn from_bytes(input: &'a [u8]) -> Result<(&[u8], Self), ParserError> {
        check_canary!();

        // clarity version
        // len prefixed contract name
        // len prefixed contract code
        let parse_tag = alt((tag(&[0x01]), tag(&[0x02])));
        let parse_length_1_byte = map(be_u8, |length| std::cmp::min(length, 128u8) as usize);
        let parse_length_4_bytes = flat_map(be_u32, take);

        let mut parser = tuple((
            parse_tag,
            flat_map(parse_length_1_byte, take),
            parse_length_4_bytes,
        ));
        let (_, (_, name, code)) = parser(input)?;

        // 1-byte tag, 1-byte name_len, name, 4-byte code_len, code
        let total_length = 1 + 1 + name.len() + 4 + code.len();
        let (rem, res) = take(total_length)(input)?;

        Ok((rem, Self(res)))
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        // skip the tag. safe ecause this was checked during parsing
        ContractName::from_bytes(&self.0[1..])
            .map(|(_, res)| res)
            .map_err(|e| e.into())
    }

    #[inline(never)]
    fn get_contract_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        match display_idx {
            0 => {
                writer_key
                    .write_str("Contract Name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                let name = self.contract_name()?;
                zxformat::pageString(out_value, name.name(), page_idx)
            }
            _ => Err(ParserError::ValueOutOfRange),
        }
    }
}

/// A transaction that instantiates a smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionSmartContract<'a>(&'a [u8]);

impl<'a> TransactionSmartContract<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), ParserError> {
        check_canary!();

        // len prefixed contract name
        // len prefixed contract code
        let parse_length_1_byte = map(be_u8, |length| std::cmp::min(length, 128u8) as usize);
        let parse_length_4_bytes = flat_map(be_u32, take);

        let mut parser = tuple((flat_map(parse_length_1_byte, take), parse_length_4_bytes));
        let (_, (name, code)) = parser(bytes)?;

        // 1-byte name_len, name, 4-byte code_len, code
        let total_length = 1 + name.len() + 4 + code.len();
        let (rem, res) = take(total_length)(bytes)?;

        Ok((rem, Self(res)))
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        ContractName::from_bytes(self.0)
            .map(|(_, res)| res)
            .map_err(|e| e.into())
    }

    #[inline(never)]
    fn get_contract_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        match display_idx {
            0 => {
                writer_key
                    .write_str("Contract Name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                let name = self.contract_name()?;
                zxformat::pageString(out_value, name.name(), page_idx)
            }
            _ => Err(ParserError::ValueOutOfRange),
        }
    }
}

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
    ContractCall(TransactionContractCall<'a>),
    VersionedSmartContract(VersionedSmartContract<'a>),
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
            TransactionPayloadId::SmartContract => {
                let contract = TransactionSmartContract::from_bytes(id.0)?;
                (contract.0, Self::SmartContract(contract.1))
            }
            TransactionPayloadId::ContractCall => {
                let call = TransactionContractCall::from_bytes(id.0)?;
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
