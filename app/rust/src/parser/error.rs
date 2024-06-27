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
    parser_ok = 0,
    parser_no_data = 1,
    parser_init_context_empty = 2,
    parser_display_idx_out_of_range = 3,
    parser_display_page_out_of_range = 4,
    parser_unexpected_error = 5,
    parser_no_memory_for_state = 6,
    // Context related errors
    parser_context_mismatch = 7,
    parser_context_unexpected_size = 8,
    parser_context_invalid_chars = 9,
    parser_context_unknown_prefix = 10,
    // Required fields
    parser_required_nonce = 11,
    parser_required_method = 12,
    ////////////////////////
    // Coin specific
    parser_post_condition_failed = 13,
    parser_invalid_contract_name = 14,
    parser_invalid_asset_name = 15,
    parser_invalid_clarity_name = 16,
    parser_invalid_fungible_code = 17,
    parser_invalid_non_fungible_code = 18,
    parser_invalid_asset_info = 19,
    parser_invalid_post_condition = 20,
    parser_invalid_post_condition_principal = 21,
    parser_invalid_hash_mode = 22,
    parser_invalid_signature = 23,
    parser_invalid_pubkey_encoding = 24,
    parser_invalid_auth_type = 25,
    parser_invalid_argument_id = 26,
    parser_invalid_transaction_payload = 27,
    parser_invalid_address_version = 28,
    parser_stacks_string_too_long = 29,
    parser_unexpected_type = 30,
    parser_unexpected_buffer_end = 31,
    parser_unexpected_value = 32,
    parser_unexpected_number_items = 33,
    parser_unexpected_characters = 34,
    parser_unexpected_field = 35,
    parser_value_out_of_range = 36,
    parser_invalid_address = 37,
    parser_invalid_token_transfer_type = 38,
    parser_invalid_bytestr_message = 39,
    parser_invalid_jwt = 40,
    parser_invalid_structured_msg = 41,
    parser_crypto_error = 42,
    parser_invalid_token_transfer_principal = 43,
    parser_recursion_limit = 44,
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
