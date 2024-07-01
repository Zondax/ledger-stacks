#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![allow(clippy::upper_case_acronyms)]

use arrayvec::CapacityError;
use nom::error::ErrorKind;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
/// ParserError is the counterpart of
/// the parse_error_t in c,
/// we redeclare it here, just for interpolation
/// purposes
pub enum ParserError {
    // Generic errors
    ParserOk = 0,
    NoData = 1,
    InitContextEmpty = 2,
    DisplayIdxOutOfRange = 3,
    DisplayPageOutOfRange = 4,
    UnexpectedError = 5,
    NoMemoryForState = 6,
    // Context related errors
    ContextMismatch = 7,
    ContextUnexpectedSize = 8,
    ContextInvalidChars = 9,
    ContextUnknownPrefix = 10,
    // Required fields
    RequiredNonce = 11,
    RequiredMethod = 12,
    ////////////////////////
    // Coin specific
    PostConditionFailed = 13,
    InvalidContractName = 14,
    InvalidAssetName = 15,
    InvalidClarityName = 16,
    InvalidFungibleCode = 17,
    InvalidNonFungibleCode = 18,
    InvalidAssetInfo = 19,
    InvalidPostCondition = 20,
    InvalidPostConditionPrincipal = 21,
    InvalidHashMode = 22,
    InvalidSignature = 23,
    InvalidPubkeyEncoding = 24,
    InvalidAuthType = 25,
    InvalidArgumentId = 26,
    InvalidTransactionPayload = 27,
    InvalidAddressVersion = 28,
    StacksStringTooLong = 29,
    UnexpectedType = 30,
    UnexpectedBufferEnd = 31,
    UnexpectedValue = 32,
    UnexpectedNumberItems = 33,
    UnexpectedCharacters = 34,
    UnexpectedField = 35,
    ValueOutOfRange = 36,
    InvalidAddress = 37,
    InvalidTokenTransferType = 38,
    InvalidBytestrMessage = 39,
    InvalidJwt = 40,
    InvalidStructuredMsg = 41,
    CryptoError = 42,
    InvalidTokenTransferPrincipal = 43,
    RecursionLimit = 44,
}
impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::UnexpectedBufferEnd,
            ErrorKind::Permutation => ParserError::UnexpectedType,
            ErrorKind::TooLarge => ParserError::ValueOutOfRange,
            ErrorKind::Tag => ParserError::UnexpectedType,
            _ => ParserError::UnexpectedError,
        }
    }
}

impl<I> nom::error::ParseError<I> for ParserError {
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

impl From<CapacityError> for ParserError {
    fn from(_error: CapacityError) -> Self {
        ParserError::UnexpectedBufferEnd
    }
}

impl From<nom::Err<Self>> for ParserError {
    fn from(e: nom::Err<Self>) -> Self {
        match e {
            nom::Err::Error(e) => e,
            nom::Err::Failure(e) => e,
            nom::Err::Incomplete(_) => Self::UnexpectedBufferEnd,
        }
    }
}
