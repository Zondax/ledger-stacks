#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![allow(clippy::upper_case_acronyms)]

use nom::error::{ErrorKind, ParseError as NomError};

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
/// ParserError is the counterpart of
/// the parse_error_t in c,
/// we redeclare it here, just for interpolation
/// purposes
pub enum ParserError {
    // Generic errors
    parser_ok,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexpected_error,
    parser_no_memory_for_state,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    parser_context_unknown_prefix,
    // Required fields
    parser_required_nonce,
    parser_required_method,
    ////////////////////////
    // Coin specific
    parser_post_condition_failed,
    parser_invalid_contract_name,
    parser_invalid_asset_name,
    parser_invalid_clarity_name,
    parser_invalid_fungible_code,
    parser_invalid_non_fungible_code,
    parser_invalid_asset_info,
    parser_invalid_post_condition,
    parser_invalid_post_condition_principal,
    parser_invalid_hash_mode,
    parser_invalid_signature,
    parser_invalid_pubkey_encoding,
    parser_invalid_auth_type,
    parser_invalid_argument_id,
    parser_invalid_transaction_payload,
    parser_invalid_address_version,
    parser_stacks_string_too_long,
    parser_unexpected_type,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_value_out_of_range,
    parser_invalid_address,
    parser_invalid_token_transfer_type,
    parser_invalid_bytestr_message,
    parser_invalid_jwt,
    parser_invalid_structured_msg,
    parser_crypto_error,
    parser_invalid_token_transfer_principal,
    parser_recursion_limit,
}

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::parser_unexpected_buffer_end,
            ErrorKind::Permutation => ParserError::parser_unexpected_type,
            ErrorKind::TooLarge => ParserError::parser_value_out_of_range,
            _ => ParserError::parser_unexpected_error,
        }
    }
}

impl<I> NomError<I> for ParserError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Self::from(kind)
    }

    // We don't have enough memory resources to use here an array with the last
    // N errors to be used as a backtrace, so that, we just propagate here the latest
    // reported error
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
impl From<ParserError> for nom::Err<ParserError> {
    fn from(error: ParserError) -> Self {
        nom::Err::Error(error)
    }
}

impl From<nom::Err<Self>> for ParserError {
    fn from(e: nom::Err<Self>) -> Self {
        match e {
            nom::Err::Error(e) => e,
            nom::Err::Failure(e) => e,
            nom::Err::Incomplete(_) => Self::parser_unexpected_buffer_end,
        }
    }
}
