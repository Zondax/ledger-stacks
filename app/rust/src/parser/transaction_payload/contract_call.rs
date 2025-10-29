use core::fmt::Write;

use nom::{bytes::complete::take, sequence::tuple};
use numtoa::NumToA;

use crate::{
    check_canary,
    parser::{
        c32,
        ffi::token_info::{get_token_info, TokenInfo, TOKEN_SYMBOL_MAX_LEN},
        transaction_payload::arguments::Arguments,
        ApduPanic, ClarityName, ContractName, ParserError, PrincipalData, StacksAddress, Value,
        ValueId, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN,
    },
    zxformat::{self, format_u128_decimals, MAX_U128_FORMATTED_SIZE_DECIMAL},
};

pub const MAX_STRING_ASCII_TO_SHOW: usize = 60;
// The items in contract_call transactions are
// contract_address, contract_name and function_name
pub const CONTRACT_CALL_BASE_ITEMS: u8 = 3;
// 1 for space, 1 for '(', 1 for ')'
// for example for ammount formatting:
// 123 (STX)
const EXTRA_CHARS_FOR_FORMAT: usize = 3;

const ADDR_STACKING1: &str = "SP000000000000000000002Q6VF78";
const ADDR_STACKING2: &str = "ST000000000000000000002AMW42H";
const CONTRACT_NAME_STACKING: &str = "pox";
const FN_NAME_STACKING1: &str = "stack-stx";
const FN_NAME_STACKING2: &str = "delegate-stx";

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
enum ContractType {
    SIP10,
    Other,
}

/// A transaction that calls into a smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionContractCallWrapper<'a> {
    contract_type: ContractType,
    tx: TransactionContractCall<'a>,
}

impl<'a> TransactionContractCallWrapper<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (rem, tx) = TransactionContractCall::from_bytes(bytes)?;

        // Check if this is a SIP-10 transfer function with token info
        let is_sip10_transfer = tx.is_transfer_function() && tx.sip10_token_info().is_some();
        let contract_type = if is_sip10_transfer {
            ContractType::SIP10
        } else {
            ContractType::Other
        };
        check_canary!();
        Ok((rem, Self { contract_type, tx }))
    }

    pub fn sip10_token_info(&self) -> Option<TokenInfo<'static>> {
        self.tx.sip10_token_info()
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        self.tx.contract_name()
    }

    pub fn contract_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        self.tx.contract_address()
    }

    pub fn function_name(&self) -> Result<&[u8], ParserError> {
        self.tx.function_name()
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        self.tx.num_args()
    }

    pub fn num_items(&self, hide_sip10_details: bool) -> Result<u8, ParserError> {
        self.tx.num_items(hide_sip10_details)
    }

    pub fn get_contract_call_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
        hide_sip10_details: bool,
    ) -> Result<u8, ParserError> {
        // display_idx was already normalized
        if hide_sip10_details && self.contract_type == ContractType::SIP10 {
            return self
                .tx
                .render_sip10_transfer_args(display_idx, out_key, out_value, page_idx);
        }

        if display_idx < CONTRACT_CALL_BASE_ITEMS {
            return self
                .tx
                .get_base_items(display_idx, out_key, out_value, page_idx);
        };

        let display_idx = display_idx - CONTRACT_CALL_BASE_ITEMS;

        if self.contract_type == ContractType::SIP10 {
            self.tx
                .render_sip10_transfer_args(display_idx, out_key, out_value, page_idx)
        } else {
            self.tx
                .render_contract_call_args(display_idx, out_key, out_value, page_idx)
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.tx.raw_data()
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionContractCall<'a>(&'a [u8]);

impl<'a> TransactionContractCall<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (rem, _) = StacksAddress::from_bytes(bytes)?;
        // get contract name and function name.
        let (rem, _) = tuple((
            ContractName::from_bytes,
            ClarityName::from_bytes,
            Arguments::from_bytes,
        ))(rem)?;

        let len = bytes.len() - rem.len();
        let (rem, data) = take(len)(bytes)?;

        check_canary!();

        Ok((rem, Self(data)))
    }

    pub fn is_transfer_function(&self) -> bool {
        let transfer_function = "transfer".as_bytes();
        let function_name = self.function_name().unwrap_or_default();
        function_name == transfer_function
    }

    /// If this contract call is an known SIP-10, and
    /// it is recognized, return the token info.
    pub fn sip10_token_info(&self) -> Option<TokenInfo<'static>> {
        // Get the contract address as a C32-encoded string
        let address = self.contract_address().ok()?;

        // Get the contract name
        let contract_name = self.contract_name().ok()?;

        // Call our FFI function to look up the token info
        get_token_info(address, contract_name)
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
        if (addr == ADDR_STACKING1.as_bytes() || addr == ADDR_STACKING2.as_bytes())
            && contract_name.name() == CONTRACT_NAME_STACKING.as_bytes()
        {
            let name = self.function_name()?;
            if name == FN_NAME_STACKING1.as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("stacked uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            } else if name == FN_NAME_STACKING2.as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("delegated uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            }
        }
        Ok(())
    }

    fn render_contract_call_args(
        &'a self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let arg_num = display_idx;

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
            ValueId::BoolTrue => zxformat::pageString(out_value, "Bool: true".as_bytes(), page_idx),
            ValueId::BoolFalse => {
                zxformat::pageString(out_value, "Bool: false".as_bytes(), page_idx)
            }
            ValueId::OptionalNone => {
                zxformat::pageString(out_value, "Option: None".as_bytes(), page_idx)
            }
            ValueId::OptionalSome => {
                zxformat::pageString(out_value, "Option: Some".as_bytes(), page_idx)
            }
            ValueId::ResponseOk => {
                zxformat::pageString(out_value, "Result: Ok".as_bytes(), page_idx)
            }
            ValueId::ResponseErr => {
                zxformat::pageString(out_value, "Result: Err".as_bytes(), page_idx)
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

                data[address.len()] = b'.';
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

    fn render_sip10_transfer_args(
        &self,
        arg_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let args = self.function_args()?;
        let token_info = self
            .sip10_token_info()
            .ok_or(ParserError::UnexpectedError)?;

        let key_strings = ["Amount", "From", "To", "Memo"];

        // Check if arg_idx is within bounds
        if arg_idx as usize >= key_strings.len() {
            return Err(ParserError::DisplayIdxOutOfRange);
        }

        // Copy the key string to out_key
        let key = key_strings[arg_idx as usize].as_bytes();
        if key.len() > out_key.len() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        out_key[..key.len()].copy_from_slice(key);

        match arg_idx {
            0 => {
                // Amount
                let amount_value = args.argument_at(0)?;
                if amount_value.value_id() != ValueId::UInt {
                    return Err(ParserError::UnexpectedError);
                }

                let amount = amount_value.uint().ok_or(ParserError::UnexpectedError)?;

                // Format amount with decimals
                let formatted_amount = format_u128_decimals(amount, token_info.decimals)
                    .ok_or(ParserError::UnexpectedError)?;

                // Create a buffer for the formatted display
                let mut display_buffer =
                    [0u8; MAX_U128_FORMATTED_SIZE_DECIMAL + TOKEN_SYMBOL_MAX_LEN + EXTRA_CHARS_FOR_FORMAT];
                let mut pos = 0;

                // Copy the formatted amount
                if formatted_amount.len() > display_buffer.len() - EXTRA_CHARS_FOR_FORMAT - token_info.token_symbol.len()
                {
                    return Err(ParserError::UnexpectedBufferEnd);
                }

                // Copy formatted amount
                display_buffer[pos..pos + formatted_amount.len()]
                    .copy_from_slice(&formatted_amount);
                pos += formatted_amount.len();

                // Add space
                display_buffer[pos] = b' ';
                pos += 1;

                // Add '('
                display_buffer[pos] = b'(';
                pos += 1;

                // Copy token symbol
                display_buffer[pos..pos + token_info.token_symbol.len()]
                    .copy_from_slice(token_info.token_symbol);
                pos += token_info.token_symbol.len();

                // Add ')'
                display_buffer[pos] = b')';
                pos += 1;

                // Page the formatted string
                zxformat::pageString(out_value, &display_buffer[..pos], page_idx)
            }
            1 => {
                // Sender principal
                let sender_value = args.argument_at(1)?;
                let payload = sender_value.payload();

                match sender_value.value_id() {
                    ValueId::StandardPrincipal => {
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::pageString(out_value, &address[..address.len()], page_idx)
                    }
                    ValueId::ContractPrincipal => {
                        // holds principal_encoded address + '.' + contract_name + null terminator
                        let mut data =
                            [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];
                        let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        let contract_name = principal.contract_name().apdu_unwrap();

                        data.get_mut(..address.len())
                            .apdu_unwrap()
                            .copy_from_slice(&address[..address.len()]);

                        data[address.len()] = b'.';
                        let len = address.len() + 1;

                        data.get_mut(len..len + contract_name.len())
                            .apdu_unwrap()
                            .copy_from_slice(contract_name.name());

                        zxformat::pageString(
                            out_value,
                            &data[..len + contract_name.len()],
                            page_idx,
                        )
                    }
                    _ => Err(ParserError::UnexpectedError),
                }
            }
            2 => {
                // Recipient principal
                // Sender principal
                let recipient_value = args.argument_at(2)?;
                let payload = recipient_value.payload();

                match recipient_value.value_id() {
                    ValueId::StandardPrincipal => {
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::pageString(out_value, &address[..address.len()], page_idx)
                    }
                    ValueId::ContractPrincipal => {
                        let mut data =
                            [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];
                        let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        let contract_name = principal.contract_name().apdu_unwrap();

                        data.get_mut(..address.len())
                            .apdu_unwrap()
                            .copy_from_slice(&address[..address.len()]);

                        data[address.len()] = b'.';
                        let len = address.len() + 1;

                        data.get_mut(len..len + contract_name.len())
                            .apdu_unwrap()
                            .copy_from_slice(contract_name.name());

                        zxformat::pageString(
                            out_value,
                            &data[..len + contract_name.len()],
                            page_idx,
                        )
                    }
                    _ => Err(ParserError::UnexpectedError),
                }
            }
            3 => {
                // Memo (optional)
                let memo_value = args.argument_at(3)?;
                self.render_memo_value(&memo_value, out_value, page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    /// Renders the content of a memo field (which is an Optional type)
    /// If it's None, renders "None"
    /// If it's Some, unwraps and renders the inner value
    /// If the inner value is a complex type, renders a generic message
    fn render_memo_value(
        &self,
        memo_value: &Value<'_>,
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        match memo_value.value_id() {
            ValueId::OptionalNone => {
                // Simply render "None"
                zxformat::pageString(out_value, "None".as_bytes(), page_idx)
            }
            ValueId::OptionalSome => {
                // Extract the inner value, skipping the first byte which is the value ID
                let inner_bytes = memo_value.payload();
                if inner_bytes.is_empty() {
                    return Err(ParserError::UnexpectedBufferEnd);
                }

                // Create a new Value from the inner bytes
                let inner_value = Value(inner_bytes);

                // Now render based on the type of the inner value
                match inner_value.value_id() {
                    ValueId::UInt => {
                        let value = inner_value.uint().ok_or(ParserError::UnexpectedError)?;
                        let mut buff = [0u8; 39];
                        zxformat::pageString(
                            out_value,
                            value.numtoa_str(10, &mut buff).as_bytes(),
                            page_idx,
                        )
                    }
                    ValueId::Int => {
                        let value = inner_value.int().ok_or(ParserError::UnexpectedError)?;
                        let mut buff = [0u8; 39];
                        zxformat::pageString(
                            out_value,
                            value.numtoa_str(10, &mut buff).as_bytes(),
                            page_idx,
                        )
                    }
                    ValueId::BoolTrue => {
                        zxformat::pageString(out_value, "true".as_bytes(), page_idx)
                    }
                    ValueId::BoolFalse => {
                        zxformat::pageString(out_value, "false".as_bytes(), page_idx)
                    }
                    ValueId::StandardPrincipal => {
                        let payload = inner_value.payload();
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::pageString(out_value, &address[0..address.len()], page_idx)
                    }
                    ValueId::ContractPrincipal => {
                        let payload = inner_value.payload();
                        // holds principal_encoded address + '.' + contract_name
                        let mut data =
                            [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];
                        let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        let contract_name = principal.contract_name().apdu_unwrap();

                        data.get_mut(..address.len())
                            .apdu_unwrap()
                            .copy_from_slice(&address[0..address.len()]);

                        data[address.len()] = b'.';
                        let len = address.len() + 1;

                        data.get_mut(len..len + contract_name.len())
                            .apdu_unwrap()
                            .copy_from_slice(contract_name.name());

                        zxformat::pageString(
                            out_value,
                            &data[0..len + contract_name.len()],
                            page_idx,
                        )
                    }
                    ValueId::StringAscii => {
                        // 4 bytes encode the length of the string
                        let payload = inner_value.payload();
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
                    // For other types, just show a generic message
                    _ => zxformat::pageString(out_value, "Complex memo value".as_bytes(), page_idx),
                }
            }
            // If it's not an Optional type at all
            _ => Err(ParserError::UnexpectedError),
        }
    }

    pub fn num_items(&self, hide_sip10_details: bool) -> Result<u8, ParserError> {
        // contract-address, contract-name, function-name
        // + the number of arguments
        let num_args = self.num_args()? as u8;
        if hide_sip10_details {
            Ok(num_args)
        } else {
            num_args
                .checked_add(CONTRACT_CALL_BASE_ITEMS)
                .ok_or(ParserError::ValueOutOfRange)
        }
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

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}
