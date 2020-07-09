use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u16, be_u32, be_u64, le_u8},
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

/// Transaction signatures are validated by calculating the public key from the signature, and
/// verifying that all public keys hash to the signing account's hash.  To do so, we must preserve
/// enough information in the auth structure to recover each public key's bytes.
///
/// An auth field can be a public key or a signature.  In both cases, the public key (either given
/// in-the-raw or embedded in a signature) may be encoded as compressed or uncompressed.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum TransactionAuthFieldID {
    // types of auth fields
    PublicKeyCompressed = 0x00,
    PublicKeyUncompressed = 0x01,
    SignatureCompressed = 0x02,
    SignatureUncompressed = 0x03,
}

#[derive(Debug, PartialEq)]
pub struct TransactionAuthField<'a>(TransactionAuthFieldID, &'a [u8]);
//{
//PublicKey(StacksPublicKey),
//Signature(TransactionPublicKeyEncoding, MessageSignature),
//}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct SpendingConditionSigner<'a> {
    pub hash_mode: HashMode,
    pub signer: Hash160<'a>,
    pub nonce: u64,    // nth authorization from this account
    pub fee_rate: u64, // microSTX/compute rate offerred by this account
}

impl<'a> SpendingConditionSigner<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let hash_mode = le_u8(bytes)?;
        let mode = HashMode::from_u8(hash_mode.1).ok_or(ParserError::parser_invalid_hash_mode)?;
        let signer = Hash160::from_bytes(hash_mode.0)?;
        let nonce = be_u64(signer.0)?;
        let fee = be_u64(nonce.0)?;
        Ok((
            fee.0,
            Self {
                hash_mode: mode,
                signer: signer.1,
                nonce: nonce.1,
                fee_rate: fee.1,
            },
        ))
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

#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct SinglesigSpendingCondition<'a> {
    pub key_encoding: TransactionPublicKeyEncoding,
    pub signature: MessageSignature<'a>,
}

/// A structure that encodes enough state to authenticate
/// a transaction's execution against a Stacks address.
/// public_keys + signatures_required determines the Principal.
/// nonce is the "check number" for the Principal.
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct MultisigSpendingCondition<'a> {
    pub num_fields: u32,
    pub fields: &'a [u8], //Vec<TransactionAuthField>,
    pub signatures_required: u16,
}

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum SpendingConditionSignature<'a> {
    Singlesig(SinglesigSpendingCondition<'a>),
    Multisig(MultisigSpendingCondition<'a>),
}

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct TransactionSpendingCondition<'a> {
    signer: SpendingConditionSigner<'a>,
    signature: SpendingConditionSignature<'a>,
}

impl<'a> SinglesigSpendingCondition<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let key = le_u8(bytes)?;
        let key_encoding = match key.1 {
            0 => TransactionPublicKeyEncoding::Compressed,
            1 => TransactionPublicKeyEncoding::Uncompressed,
            _ => return Err(nom::Err::Error(ParserError::parser_invalid_pubkey_encoding)),
        };

        let signature = MessageSignature::from_bytes(key.0)
            .map_err(|_| ParserError::parser_invalid_signature)?;
        let condition = Self {
            key_encoding,
            signature: signature.1,
        };
        check_canary!();
        Ok((signature.0, condition))
    }

    pub fn key_encoding(&self) -> TransactionPublicKeyEncoding {
        self.key_encoding
    }
}

impl<'a> MultisigSpendingCondition<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        // first get the number of auth-fields
        let (raw, num_fields) = be_u32(bytes)?;
        let mut bytes_count = 0usize;
        for _ in 0..num_fields {
            match raw[bytes_count] {
                0x00 | 0x01 => {
                    bytes_count += 33 + 1;
                }
                0x02 | 0x03 => {
                    bytes_count += 65 + 1;
                }
                _ => return Err(nom::Err::Error(ParserError::parser_unexpected_value)),
            }
        }

        let (raw1, fields) = take(bytes_count)(raw)?;
        let (raw2, signatures_required) = be_u16(raw1)?;
        Ok((
            raw2,
            Self {
                num_fields,
                fields,
                signatures_required,
            },
        ))
    }

    pub fn required_signatures(&self) -> u16 {
        self.signatures_required
    }

    pub fn num_fields(&self) -> u32 {
        self.num_fields
    }
}

impl<'a> TransactionSpendingCondition<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, signer) = SpendingConditionSigner::from_bytes(bytes)?;
        let (leftover, signature) = match signer.hash_mode {
            HashMode::P2PKH | HashMode::P2WPKH => {
                let sig = SinglesigSpendingCondition::from_bytes(raw)?;
                (sig.0, SpendingConditionSignature::Singlesig(sig.1))
            }
            HashMode::P2WSH | HashMode::P2SH => {
                let sig = MultisigSpendingCondition::from_bytes(raw)?;
                (sig.0, SpendingConditionSignature::Multisig(sig.1))
            }
        };
        Ok((leftover, Self { signer, signature }))
    }

    pub fn signer_address(
        &self,
        chain: TransactionVersion,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        self.signer.signer_address(chain)
    }

    pub fn nonce_str(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        self.signer.nonce_str()
    }

    pub fn fee_str(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        self.signer.fee_str()
    }

    pub fn nonce(&self) -> u64 {
        self.signer.nonce
    }

    pub fn fee(&self) -> u64 {
        self.signer.fee_rate
    }

    pub fn is_single_signature(&self) -> bool {
        match self.signature {
            SpendingConditionSignature::Singlesig(..) => true,
            _ => false,
        }
    }

    pub fn is_multi_signature(&self) -> bool {
        match self.signature {
            SpendingConditionSignature::Multisig(..) => true,
            _ => false,
        }
    }

    pub fn num_auth_fields(&self) -> Option<u32> {
        match self.signature {
            SpendingConditionSignature::Multisig(ref sig) => Some(sig.num_fields()),
            _ => None,
        }
    }

    pub fn required_signatures(&self) -> Option<u16> {
        match self.signature {
            SpendingConditionSignature::Multisig(ref sig) => Some(sig.required_signatures()),
            _ => None,
        }
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
        //let spending_condition_p2pkh_uncompressed = TransactionSpendingCondition {
        let spending_condition_signer = SpendingConditionSigner {
            signer: Hash160(hash.as_ref()),
            hash_mode: HashMode::P2PKH,
            nonce: 123,
            fee_rate: 456,
        };
        let spending_condition_p2pkh_uncompressed = TransactionSpendingCondition {
            signer: spending_condition_signer,
            signature: SpendingConditionSignature::Singlesig(SinglesigSpendingCondition {
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                signature: MessageSignature(sign_uncompressed.as_ref()),
            }),
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

        let spending_condition_signer = SpendingConditionSigner {
            signer: Hash160(hash.as_ref()),
            hash_mode: HashMode::P2PKH,
            nonce: 345,
            fee_rate: 456,
        };
        let spending_condition_p2pkh_compressed = TransactionSpendingCondition {
            signer: spending_condition_signer,
            signature: SpendingConditionSignature::Singlesig(SinglesigSpendingCondition {
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature(sign_compressed.as_ref()),
            }),
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

        let spending_condition_signer = SpendingConditionSigner {
            signer: Hash160(hash.as_ref()),
            hash_mode: HashMode::P2WPKH,
            nonce: 345,
            fee_rate: 567,
        };
        let spending_condition_p2pwkh_compressed = TransactionSpendingCondition {
            signer: spending_condition_signer,
            signature: SpendingConditionSignature::Singlesig(SinglesigSpendingCondition {
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature(sign_compressed.as_ref()),
            }),
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
            HashMode::P2WSH as u8,
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

    #[test]
    fn tx_spending_condition_p2sh() {
        // p2sh

        let spending_condition_p2sh_uncompressed_bytes = vec![
            // hash mode
            HashMode::P2SH as u8,
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
            // fields length
            0x00,
            0x00,
            0x00,
            0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // field #1: signature
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
            // field #2: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // filed #2: signature
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
            // field #3: public key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            // field #3: key (compressed)
            0x03,
            0xef,
            0x23,
            0x40,
            0x51,
            0x8b,
            0x58,
            0x67,
            0xb2,
            0x35,
            0x98,
            0xa9,
            0xcf,
            0x74,
            0x61,
            0x1f,
            0x8b,
            0x98,
            0x06,
            0x4f,
            0x7d,
            0x55,
            0xcd,
            0xb8,
            0xc1,
            0x07,
            0xc6,
            0x7b,
            0x5e,
            0xfc,
            0xbc,
            0x5c,
            0x77,
            // number of signatures required
            0x00,
            0x02,
        ];

        let (_raw, decoded) = TransactionSpendingCondition::from_bytes(
            spending_condition_p2sh_uncompressed_bytes.as_ref(),
        )
        .unwrap();

        assert_eq!(2, decoded.required_signatures().unwrap());
        assert_eq!(3, decoded.num_auth_fields().unwrap());

        assert_eq!(123, decoded.nonce());
        assert_eq!(456, decoded.fee());

        let spending_condition_p2sh_compressed_bytes = vec![
            // hash mode
            HashMode::P2SH as u8,
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
            // fields length
            0x00,
            0x00,
            0x00,
            0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
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
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
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
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03,
            0xef,
            0x23,
            0x40,
            0x51,
            0x8b,
            0x58,
            0x67,
            0xb2,
            0x35,
            0x98,
            0xa9,
            0xcf,
            0x74,
            0x61,
            0x1f,
            0x8b,
            0x98,
            0x06,
            0x4f,
            0x7d,
            0x55,
            0xcd,
            0xb8,
            0xc1,
            0x07,
            0xc6,
            0x7b,
            0x5e,
            0xfc,
            0xbc,
            0x5c,
            0x77,
            // number of signatures
            0x00,
            0x02,
        ];

        let (_raw, decoded) = TransactionSpendingCondition::from_bytes(
            spending_condition_p2sh_compressed_bytes.as_ref(),
        )
        .unwrap();
        assert_eq!(2, decoded.required_signatures().unwrap());
        assert_eq!(3, decoded.num_auth_fields().unwrap());

        assert_eq!(456, decoded.nonce());
        assert_eq!(567, decoded.fee());
    }

    #[test]
    fn tx_spending_condition_p2wsh() {
        let spending_condition_p2wsh_bytes = vec![
            // hash mode
            HashMode::P2WSH as u8,
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
            // fields length
            0x00,
            0x00,
            0x00,
            0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
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
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
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
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03,
            0xef,
            0x23,
            0x40,
            0x51,
            0x8b,
            0x58,
            0x67,
            0xb2,
            0x35,
            0x98,
            0xa9,
            0xcf,
            0x74,
            0x61,
            0x1f,
            0x8b,
            0x98,
            0x06,
            0x4f,
            0x7d,
            0x55,
            0xcd,
            0xb8,
            0xc1,
            0x07,
            0xc6,
            0x7b,
            0x5e,
            0xfc,
            0xbc,
            0x5c,
            0x77,
            // number of signatures
            0x00,
            0x02,
        ];

        let (_raw, decoded) =
            TransactionSpendingCondition::from_bytes(spending_condition_p2wsh_bytes.as_ref())
                .unwrap();
        assert_eq!(2, decoded.required_signatures().unwrap());
        assert_eq!(3, decoded.num_auth_fields().unwrap());

        assert_eq!(456, decoded.nonce());
        assert_eq!(567, decoded.fee());
    }
}
