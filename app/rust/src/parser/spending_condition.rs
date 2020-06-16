use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::parser::parser_common::{Hash160, HashMode, ParserError, SIGNATURE_LEN};

// Signature
// should by 65-bytes length
#[repr(C)]
pub struct MessageSignature<'a>(&'a [u8]);

impl<'a> MessageSignature<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let signature = take(SIGNATURE_LEN)(bytes)?;
        Ok((signature.0, Self(signature.1)))
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum TransactionPublicKeyEncoding {
    // ways we can encode a public key
    Compressed = 0x00,
    Uncompressed = 0x01,
}

#[repr(C)]
pub struct TransactionSpendingCondition<'a> {
    pub hash_mode: HashMode,
    pub signer: Hash160<'a>,
    pub nonce: u64,    // nth authorization from this account
    pub fee_rate: u64, // microSTX/compute rate offerred by this account
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature<'a>,
}

impl<'a> TransactionSpendingCondition<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let hash_mode = le_u8(bytes)?;
        let mode = HashMode::from_u8(hash_mode.1).ok_or(ParserError::parser_invalid_hash_mode)?;
        let hash160 = Hash160::from_bytes(hash_mode.0)?;
        let nonce = be_u64(hash160.0)?;
        let fee = be_u64(nonce.0)?;
        let key = le_u8(fee.0)?;
        let key_encoding = match key.1 {
            0 => TransactionPublicKeyEncoding::Compressed,
            1 => TransactionPublicKeyEncoding::Uncompressed,
            _ => return Err(nom::Err::Error(ParserError::parser_invalid_pubkey_encoding)),
        };
        let signature = MessageSignature::from_bytes(key.0)
            .map_err(|_| ParserError::parser_invalid_signature)?;
        let condition = Self {
            hash_mode: mode,
            signer: hash160.1,
            nonce: nonce.1,
            fee_rate: fee.1,
            key_encoding,
            signature: signature.1,
        };
        Ok((signature.0, condition))
    }
}
