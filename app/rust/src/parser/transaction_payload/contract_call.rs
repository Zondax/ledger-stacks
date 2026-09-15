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
// A SIP-10 `transfer` takes (amount uint) (sender principal) (recipient principal)
// (memo (optional (buff 34))) -- the four items render_sip10_transfer_args displays.
const SIP10_TRANSFER_ARGS: u32 = 4;
const SIP10_MEMO_ARG_IDX: usize = 3;
// 1 for space, 1 for '(', 1 for ')'
// for example for ammount formatting:
// 123 (STX)
const EXTRA_CHARS_FOR_FORMAT: usize = 3;

const ADDR_STACKING1: &str = "SP000000000000000000002Q6VF78";
const ADDR_STACKING2: &str = "ST000000000000000000002AMW42H";
const FN_NAME_STACKING1: &str = "stack-stx";
const FN_NAME_STACKING2: &str = "delegate-stx";

/// Matches a boot PoX contract name: `pox` or `pox-N` (`pox-2`, `pox-3`, `pox-4`, ...).
/// Versioned so the friendly stacking labels keep applying to whichever PoX contract is
/// active at a given epoch, rather than pinning a single version.
fn is_pox_contract_name(name: &[u8]) -> bool {
    if name == b"pox" {
        return true;
    }
    match name.strip_prefix(b"pox-") {
        Some(rest) => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
        None => false,
    }
}

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

    /// Whether this call is rendered through the compact SIP-10 transfer card.
    ///
    /// The renderer keys the compact card off `ContractType::SIP10`, which additionally requires
    /// the called function to be `transfer`. Any predicate that suppresses items must agree with
    /// it, or `num_items` and `get_item` disagree on how many slots the payload occupies.
    pub fn is_sip10_transfer(&self) -> bool {
        self.contract_type == ContractType::SIP10
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

    /// A contract call must be blind-signed when any argument shown to the user renders as a
    /// type placeholder rather than its actual value.
    ///
    /// Mirrors how [`Self::get_contract_call_items`] dispatches *arguments*: a SIP-10 transfer
    /// always renders them through `render_sip10_transfer_args`, whatever `hide_sip10_details`
    /// says -- that flag only controls whether the base items and post-conditions are shown, not
    /// how the arguments themselves are displayed. Keying this off `hide_sip10_details` would
    /// wrongly gate a SIP-10 transfer whose memo the device renders perfectly well.
    pub fn requires_blindsign(&self) -> Result<bool, ParserError> {
        let args = self.tx.function_args()?;

        if self.contract_type == ContractType::SIP10 {
            // render_sip10_transfer_args shows exactly Amount / From / To / Memo. It type-checks
            // the first three and errors if they are not a uint and two principals, so the memo
            // is the only item that can silently degrade (to "Complex memo value").
            if self.tx.num_args()? != SIP10_TRANSFER_ARGS {
                return Ok(true);
            }
            let memo = args.argument_at(SIP10_MEMO_ARG_IDX)?;
            return Ok(!TransactionContractCall::memo_is_fully_displayable(&memo));
        }

        args.all(TransactionContractCall::arg_is_fully_displayable)
            .map(|all_displayable| !all_displayable)
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
            && is_pox_contract_name(contract_name.name())
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

    /// Whether `render_contract_call_args` below can show this value in full, or only degrades
    /// to a type placeholder such as `"is Tuple"`.
    ///
    /// SINGLE SOURCE OF TRUTH for the blind-signing gate. The arms here must mirror the
    /// placeholder arms of [`Self::render_contract_call_args`] exactly: if a value renders as a
    /// placeholder, the user is signing bytes they cannot see, and the transaction must be gated.
    /// `test_displayable_predicate_matches_renderer` enforces the correspondence mechanically, so
    /// teaching the renderer a new type without moving it here fails the build.
    pub fn arg_is_fully_displayable(value: &Value) -> bool {
        match value.value_id() {
            ValueId::Int
            | ValueId::UInt
            | ValueId::BoolTrue
            | ValueId::BoolFalse
            // "Option: None" *is* the complete value, not a placeholder.
            | ValueId::OptionalNone
            | ValueId::StandardPrincipal
            | ValueId::ContractPrincipal => true,

            // Rendered, but silently truncated past MAX_STRING_ASCII_TO_SHOW.
            ValueId::StringAscii => Self::string_ascii_fits(value),

            // Only the type name is rendered; the value itself is never shown to the user.
            ValueId::Buffer
            | ValueId::List
            | ValueId::Tuple
            | ValueId::StringUtf8
            // These render as "Option: Some" / "Result: Ok" / "Result: Err" -- the inner
            // value, which is the part that matters, is never displayed.
            | ValueId::OptionalSome
            | ValueId::ResponseOk
            | ValueId::ResponseErr => false,
        }
    }

    /// A StringAscii payload is `[len: 4][chars]`. The renderer truncates, without any ellipsis,
    /// once the string exceeds MAX_STRING_ASCII_TO_SHOW, so anything longer hides data.
    fn string_ascii_fits(value: &Value) -> bool {
        match value.payload().len().checked_sub(4) {
            Some(str_len) => str_len <= MAX_STRING_ASCII_TO_SHOW,
            // Malformed (payload shorter than the length prefix); be conservative.
            None => false,
        }
    }

    /// Whether [`Self::render_memo_value`] can show this memo in full.
    ///
    /// Mirrors that function's match arms; see `arg_is_fully_displayable` for why this matters.
    /// Note the memo path *unwraps* `OptionalSome`, which the generic argument path does not.
    pub fn memo_is_fully_displayable(memo: &Value) -> bool {
        match memo.value_id() {
            ValueId::OptionalNone => true,
            ValueId::OptionalSome => {
                let inner_bytes = memo.payload();
                if inner_bytes.is_empty() {
                    return false;
                }
                let inner = Value(inner_bytes);
                match inner.value_id() {
                    ValueId::UInt
                    | ValueId::Int
                    | ValueId::BoolTrue
                    | ValueId::BoolFalse
                    | ValueId::StandardPrincipal
                    | ValueId::ContractPrincipal => true,
                    ValueId::StringAscii => Self::string_ascii_fits(&inner),
                    // Everything else renders as "Complex memo value".
                    _ => false,
                }
            }
            // render_memo_value errors on a non-Optional memo; be conservative.
            _ => false,
        }
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

        // The first uint argument of a PoX stack-stx/delegate-stx call gets a friendlier key.
        if arg_num == 0 && value.value_id() == ValueId::UInt {
            self.label_stacking_value(out_key)?;
        }

        Self::render_value(&value, out_value, page_idx)
    }

    /// Renders a single contract-call argument value into `out_value`.
    ///
    /// Kept as a standalone function so `arg_is_fully_displayable` can be checked against the
    /// real rendering behaviour rather than a restatement of it -- see
    /// `test_displayable_predicate_matches_renderer`.
    fn render_value(
        value: &Value,
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // return the value content including the valueID
        let payload = value.payload();

        match value.value_id() {
            ValueId::Int => {
                let value = value.int().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 41]; // 40 digits + possible sign

                // Handle i128::MIN specially as numtoa has a bug with it
                // (it causes underflow when computing the absolute value)
                if value == i128::MIN {
                    let min_str = b"-170141183460469231731687303715884105728";
                    zxformat::page_string(out_value, min_str, page_idx)
                } else {
                    zxformat::page_string(
                        out_value,
                        value.numtoa_str(10, &mut buff).as_bytes(),
                        page_idx,
                    )
                }
            }
            ValueId::UInt => {
                let value = value.uint().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 39];

                zxformat::page_string(
                    out_value,
                    value.numtoa_str(10, &mut buff).as_bytes(),
                    page_idx,
                )
            }
            ValueId::BoolTrue => zxformat::page_string(out_value, "Bool: true".as_bytes(), page_idx),
            ValueId::BoolFalse => {
                zxformat::page_string(out_value, "Bool: false".as_bytes(), page_idx)
            }
            ValueId::OptionalNone => {
                zxformat::page_string(out_value, "Option: None".as_bytes(), page_idx)
            }
            ValueId::OptionalSome => {
                zxformat::page_string(out_value, "Option: Some".as_bytes(), page_idx)
            }
            ValueId::ResponseOk => {
                zxformat::page_string(out_value, "Result: Ok".as_bytes(), page_idx)
            }
            ValueId::ResponseErr => {
                zxformat::page_string(out_value, "Result: Err".as_bytes(), page_idx)
            }
            ValueId::StandardPrincipal => {
                let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                let address = principal.encoded_address()?;
                zxformat::page_string(out_value, &address[0..address.len()], page_idx)
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

                zxformat::page_string(out_value, &data[0..len + contract_name.len()], page_idx)
            }
            ValueId::Buffer => zxformat::page_string(out_value, "is Buffer".as_bytes(), page_idx),
            ValueId::List => zxformat::page_string(out_value, "is List".as_bytes(), page_idx),
            ValueId::Tuple => zxformat::page_string(out_value, "is Tuple".as_bytes(), page_idx),
            ValueId::StringAscii => {
                // 4 bytes encode the length of the string
                let len = if payload.len() - 4 > MAX_STRING_ASCII_TO_SHOW {
                    MAX_STRING_ASCII_TO_SHOW
                } else {
                    payload.len()
                };
                zxformat::page_string(
                    out_value,
                    &payload[4..len], // omit the first 4-bytes as they are the string length
                    page_idx,
                )
            }

            ValueId::StringUtf8 => {
                zxformat::page_string(out_value, "is StringUtf8".as_bytes(), page_idx)
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
                zxformat::page_string(out_value, &display_buffer[..pos], page_idx)
            }
            1 => {
                // Sender principal
                let sender_value = args.argument_at(1)?;
                let payload = sender_value.payload();

                match sender_value.value_id() {
                    ValueId::StandardPrincipal => {
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::page_string(out_value, &address[..address.len()], page_idx)
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

                        zxformat::page_string(
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
                        zxformat::page_string(out_value, &address[..address.len()], page_idx)
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

                        zxformat::page_string(
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
                zxformat::page_string(out_value, "None".as_bytes(), page_idx)
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
                        zxformat::page_string(
                            out_value,
                            value.numtoa_str(10, &mut buff).as_bytes(),
                            page_idx,
                        )
                    }
                    ValueId::Int => {
                        let value = inner_value.int().ok_or(ParserError::UnexpectedError)?;
                        let mut buff = [0u8; 41];
                        // Handle i128::MIN specially as numtoa has a bug with it
                        if value == i128::MIN {
                            let min_str = b"-170141183460469231731687303715884105728";
                            zxformat::page_string(out_value, min_str, page_idx)
                        } else {
                            zxformat::page_string(
                                out_value,
                                value.numtoa_str(10, &mut buff).as_bytes(),
                                page_idx,
                            )
                        }
                    }
                    ValueId::BoolTrue => {
                        zxformat::page_string(out_value, "true".as_bytes(), page_idx)
                    }
                    ValueId::BoolFalse => {
                        zxformat::page_string(out_value, "false".as_bytes(), page_idx)
                    }
                    ValueId::StandardPrincipal => {
                        let payload = inner_value.payload();
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::page_string(out_value, &address[0..address.len()], page_idx)
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

                        zxformat::page_string(
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
                        zxformat::page_string(
                            out_value,
                            &payload[4..len], // omit the first 4-bytes as they are the string length
                            page_idx,
                        )
                    }
                    // For other types, just show a generic message
                    _ => zxformat::page_string(out_value, "Complex memo value".as_bytes(), page_idx),
                }
            }
            // If it's not an Optional type at all
            _ => Err(ParserError::UnexpectedError),
        }
    }

    pub fn num_items(&self, hide_sip10_details: bool) -> Result<u8, ParserError> {
        // contract-address, contract-name, function-name
        // + the number of arguments
        let raw_args = self.num_args()?;
        if raw_args > u8::MAX as u32 {
            return Err(ParserError::ValueOutOfRange);
        }
        let num_args = raw_args as u8;
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
                zxformat::page_string(out_value, address.as_ref(), page_idx)
            }
            // Contract.name
            1 => {
                writer_key
                    .write_str("Contract name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.contract_name()?;
                check_canary!();
                zxformat::page_string(out_value, name.name(), page_idx)
            }
            // Function-name
            2 => {
                writer_key
                    .write_str("Function name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.function_name()?;
                check_canary!();
                zxformat::page_string(out_value, name, page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::TX_DEPTH_LIMIT;
    use std::prelude::v1::*;

    /// Exactly the strings `render_value` emits in place of a value it cannot show.
    const PLACEHOLDERS: &[&str] = &[
        "is Buffer",
        "is List",
        "is Tuple",
        "is StringUtf8",
        "Option: Some",
        "Result: Ok",
        "Result: Err",
    ];

    fn int(v: i128) -> Vec<u8> {
        let mut b = vec![0x00];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn uint(v: u128) -> Vec<u8> {
        let mut b = vec![0x01];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn buffer() -> Vec<u8> {
        let mut b = vec![0x02, 0, 0, 0, 3];
        b.extend_from_slice(b"abc");
        b
    }

    fn std_principal() -> Vec<u8> {
        let mut b = vec![0x05, 26];
        b.extend_from_slice(&[0x11; 20]);
        b
    }

    fn contract_principal() -> Vec<u8> {
        let mut b = vec![0x06, 26];
        b.extend_from_slice(&[0x11; 20]);
        b.push(13);
        b.extend_from_slice(b"some-contract");
        b
    }

    /// `[0x0b][num_items: 4][values..]`
    fn list() -> Vec<u8> {
        let mut b = vec![0x0b, 0, 0, 0, 2];
        b.extend_from_slice(&uint(1));
        b.extend_from_slice(&uint(2));
        b
    }

    /// `[0x0c][num_pairs: 4][(name_len, name, value)..]` -- shaped like a PoX `pox-addr`.
    fn tuple() -> Vec<u8> {
        let mut b = vec![0x0c, 0, 0, 0, 1];
        b.push(7);
        b.extend_from_slice(b"version");
        b.extend_from_slice(&uint(1));
        b
    }

    fn string_ascii(len: usize) -> Vec<u8> {
        let mut b = vec![0x0d];
        b.extend_from_slice(&(len as u32).to_be_bytes());
        b.resize(b.len() + len, b'a');
        b
    }

    fn string_utf8() -> Vec<u8> {
        let mut b = vec![0x0e, 0, 0, 0, 3];
        b.extend_from_slice("abc".as_bytes());
        b
    }

    /// Wraps `inner` in a single-byte-tagged container (OptionalSome / ResponseOk / ResponseErr).
    fn wrap(id: u8, inner: Vec<u8>) -> Vec<u8> {
        let mut b = vec![id];
        b.extend_from_slice(&inner);
        b
    }

    /// One valid encoding per ValueId variant.
    fn samples() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("Int", int(-1)),
            ("UInt", uint(7)),
            ("Buffer", buffer()),
            ("BoolTrue", vec![0x03]),
            ("BoolFalse", vec![0x04]),
            ("StandardPrincipal", std_principal()),
            ("ContractPrincipal", contract_principal()),
            ("ResponseOk", wrap(0x07, uint(1))),
            ("ResponseErr", wrap(0x08, uint(1))),
            ("OptionalNone", vec![0x09]),
            ("OptionalSome", wrap(0x0a, uint(1))),
            ("List", list()),
            ("Tuple", tuple()),
            ("StringAscii", string_ascii(10)),
            ("StringUtf8", string_utf8()),
        ]
    }

    fn parse(bytes: &[u8]) -> Value<'_> {
        Value::from_bytes::<TX_DEPTH_LIMIT>(bytes)
            .expect("sample must be a valid Clarity value")
            .1
    }

    fn render(bytes: &[u8]) -> String {
        let value = parse(bytes);
        let mut out = [0u8; 200];
        TransactionContractCall::render_value(&value, &mut out, 0).expect("render_value failed");
        let end = out.iter().position(|&c| c == 0).unwrap_or(out.len());
        String::from_utf8(out[..end].to_vec()).expect("rendered value must be utf8")
    }

    fn displayable(bytes: &[u8]) -> bool {
        TransactionContractCall::arg_is_fully_displayable(&parse(bytes))
    }

    /// The blind-signing gate is only sound if `arg_is_fully_displayable` returns false for
    /// *exactly* the values `render_value` degrades to a placeholder. Teaching the renderer a new
    /// type without updating the predicate would silently sign un-displayed data with no warning;
    /// the reverse would gate transactions the user can actually review.
    #[test]
    fn test_displayable_predicate_matches_renderer() {
        for (name, bytes) in samples() {
            let rendered = render(&bytes);
            let is_placeholder = PLACEHOLDERS.contains(&rendered.as_str());
            assert_eq!(
                displayable(&bytes),
                !is_placeholder,
                "{name}: predicate disagrees with renderer (rendered {rendered:?})"
            );
        }
    }

    /// `arg_is_fully_displayable` matches exhaustively on ValueId, so a new variant breaks the
    /// build there. This keeps the sample table above honest about covering every variant.
    #[test]
    fn test_samples_cover_every_value_id() {
        assert_eq!(samples().len(), 15);
    }

    #[test]
    fn test_placeholders_are_the_opaque_types() {
        for (name, bytes) in samples() {
            let opaque = matches!(
                name,
                "Buffer" | "List" | "Tuple" | "StringUtf8" | "OptionalSome" | "ResponseOk" | "ResponseErr"
            );
            assert_eq!(displayable(&bytes), !opaque, "{name} classified wrongly");
        }
    }

    #[test]
    fn test_string_ascii_truncation_requires_blindsign() {
        // Rendered in full up to the cap...
        assert!(displayable(&string_ascii(MAX_STRING_ASCII_TO_SHOW)));
        // ...but silently truncated past it, with no ellipsis, so the user cannot see what
        // they are signing.
        assert!(!displayable(&string_ascii(MAX_STRING_ASCII_TO_SHOW + 1)));
    }

    /// The SIP-10 memo path unwraps `Some(..)` and renders the inner value, which the generic
    /// argument path does not. The two predicates must track their own renderers, not each other.
    #[test]
    fn test_memo_predicate_unwraps_optional_some() {
        let some_uint = wrap(0x0a, uint(1));
        assert!(TransactionContractCall::memo_is_fully_displayable(&parse(&some_uint)));
        assert!(!TransactionContractCall::arg_is_fully_displayable(&parse(&some_uint)));

        // A (some (buff ..)) memo renders "Complex memo value" -- opaque.
        let some_buff = wrap(0x0a, buffer());
        assert!(!TransactionContractCall::memo_is_fully_displayable(&parse(&some_buff)));

        let none = vec![0x09u8];
        assert!(TransactionContractCall::memo_is_fully_displayable(&parse(&none)));
    }
}
