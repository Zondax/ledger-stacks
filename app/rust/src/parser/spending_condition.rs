use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use arrayvec::ArrayVec;

use crate::check_canary;
use crate::parser::parser_common::{
    Hash160, HashMode, ParserError, TransactionVersion, C32_ENCODED_ADDRS_LENGTH, SIGNATURE_LEN,
};
use crate::parser::{c32, ffi::fp_uint64_to_str};
use crate::zxformat;

// Signature
// should by 65-bytes length
#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct MessageSignature<'a>(&'a [u8]);

impl<'a> MessageSignature<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let signature = take(SIGNATURE_LEN)(bytes)?;
        Ok((signature.0, Self(signature.1)))
    }
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionPublicKeyEncoding {
    // ways we can encode a public key
    Compressed = 0x00,
    Uncompressed = 0x01,
}

impl TransactionPublicKeyEncoding {
    // BIPs 141 and 143 make it very clear that P2WPKH scripts may be only derived
    // from compressed public-keys
    fn is_valid_hash_mode(self, mode: HashMode) -> bool {
        if mode == HashMode::P2WPKH && self != Self::Compressed {
            return false;
        }
        true
    }
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct TransactionSpendingCondition<'a> {
    pub hash_mode: HashMode,
    pub signer: Hash160<'a>,
    pub nonce: u64,    // nth authorization from this account
    pub fee_rate: u64, // microSTX/compute rate offerred by this account
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature<'a>,
}

impl<'a> TransactionSpendingCondition<'a> {
    #[inline(never)]
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

        if !key_encoding.is_valid_hash_mode(mode) {
            return Err(nom::Err::Error(ParserError::parser_invalid_pubkey_encoding));
        }

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
        check_canary!();
        Ok((signature.0, condition))
    }

    pub fn signer_address(
        &self,
        chain: TransactionVersion,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        if chain == TransactionVersion::Testnet {
            self.signer.to_testnet_address(self.hash_mode)
        } else {
            self.signer.to_mainnet_address(self.hash_mode)
        }
    }

    pub fn nonce_str(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
        let len = if cfg!(test) {
            zxformat::u64_to_str(&mut output[..zxformat::MAX_STR_BUFF_LEN], self.nonce)? as usize
        } else {
            unsafe {
                fp_uint64_to_str(
                    output.as_mut_ptr() as _,
                    zxformat::MAX_STR_BUFF_LEN as u16,
                    self.nonce,
                    0,
                ) as usize
            }
        };
        unsafe {
            output.set_len(len);
        }
        Ok(output)
    }

    pub fn fee_str(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
        let len = if cfg!(test) {
            zxformat::fpu64_to_str(output.as_mut(), self.fee_rate, 0)? as usize
        } else {
            unsafe {
                fp_uint64_to_str(
                    output.as_mut_ptr() as _,
                    zxformat::MAX_STR_BUFF_LEN as u16,
                    self.fee_rate,
                    0,
                ) as usize
            }
        };
        unsafe {
            output.set_len(len);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use serde_json::{Result, Value};

    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::string::String;
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn test_spending_condition_p2pkh() {
        // p2pkh
        let hash = [0x11; 20];
        let sign_uncompressed = [0xff; 65];
        let sign_compressed = [0xfe; 65];
        let spending_condition_p2pkh_uncompressed = TransactionSpendingCondition {
            signer: Hash160(hash.as_ref()),
            hash_mode: HashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 123,
            fee_rate: 456,
            signature: MessageSignature(sign_uncompressed.as_ref()),
        };

        let spending_condition_p2pkh_uncompressed_bytes = vec![
            // hash mode
            HashMode::P2PKH as u8,
            // signer
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            // nonce
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x7b,
            // fee rate
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0xc8,
            // key encoding,
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
        ];

        let spending_condition_p2pkh_compressed = TransactionSpendingCondition {
            signer: Hash160(hash.as_ref()),
            hash_mode: HashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            fee_rate: 456,
            signature: MessageSignature(sign_compressed.as_ref()),
        };

        let spending_condition_p2pkh_compressed_bytes = vec![
            // hash mode
            HashMode::P2PKH as u8,
            // signer
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            // nonce
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x59,
            // fee rate
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0xc8,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
        ];

        /*spending_condition_p2pkh_compressed,
        spending_condition_p2pkh_uncompressed,*/

        let (bytes, compressed) =
            TransactionSpendingCondition::from_bytes(&spending_condition_p2pkh_compressed_bytes)
                .unwrap();
        assert_eq!(spending_condition_p2pkh_compressed, compressed);
        assert_eq!(bytes.len(), 0);

        let (bytes, uncompressed) =
            TransactionSpendingCondition::from_bytes(&spending_condition_p2pkh_uncompressed_bytes)
                .unwrap();
        assert_eq!(spending_condition_p2pkh_uncompressed, uncompressed);
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_spending_condition_p2wpkh() {
        let hash = [0x11; 20];
        let sign_compressed = [0xfe; 65];
        let spending_condition_p2pwkh_compressed = TransactionSpendingCondition {
            signer: Hash160(hash.as_ref()),
            hash_mode: HashMode::P2WPKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            fee_rate: 567,
            signature: MessageSignature(sign_compressed.as_ref()),
        };

        let spending_condition_p2wpkh_compressed_bytes = vec![
            // hash mode
            HashMode::P2WPKH as u8,
            // signer
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            // nonce
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x59,
            // fee rate
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            0x37,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
            0xfe,
        ];

        let (bytes, decoded) =
            TransactionSpendingCondition::from_bytes(&spending_condition_p2wpkh_compressed_bytes)
                .unwrap();
        assert_eq!(bytes.len(), 0);
        assert_eq!(spending_condition_p2pwkh_compressed, decoded);
    }

    #[test]
    fn test_invalid_spending_conditions() {
        let bad_hash_mode_bytes = vec![
            // singlesig
            // hash mode
            0xff,
            // signer
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            // nonce
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0xc8,
            // fee rate
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
            0xfd,
        ];
        let bad_hash_mode = TransactionSpendingCondition::from_bytes(&bad_hash_mode_bytes);
        assert!(bad_hash_mode.is_err());

        let bad_p2wpkh_uncompressed_bytes = vec![
            // hash mode
            HashMode::P2WPKH as u8,
            // signer
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            0x11,
            // nonce
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x7b,
            // fee rate
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            0x37,
            // public key uncompressed
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
        ];
        let bad_signature =
            TransactionSpendingCondition::from_bytes(&bad_p2wpkh_uncompressed_bytes);
        assert!(bad_signature.is_err());
    }
}
