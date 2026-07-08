//! Stacks multisig (P2SH) address derivation.
//!
//! A Stacks P2SH address is `c32check(version, Hash160(redeem_script))` where the
//! redeem script is the Bitcoin-style multisig script
//! `OP_m  ( push_len | pubkey ) * n  OP_n  OP_CHECKMULTISIG`
//! and `Hash160 = RIPEMD160(SHA256(redeem_script))`.
//!
//! The device derives its own public key and the host supplies the other
//! cosigner keys; this module splices the device key into the ordered set at
//! `device_index`, builds the script, hashes it, and c32-encodes the result.

use arrayvec::ArrayVec;

use crate::bolos::{ripemd160, sha256, SHA256_LEN};
use crate::parser::c32::c32_address;
use crate::parser::error::ParserError;
use crate::parser::parser_common::{C32_ENCODED_ADDRS_LENGTH, HASH160_LEN, PUBKEY_LEN};

/// OP_CHECKMULTISIG opcode.
const OP_CHECKMULTISIG: u8 = 0xae;

/// Maximum number of participating keys. The 520-byte P2SH redeem-script limit
/// caps a Stacks multisig at 15 compressed keys (matches stacks.js).
pub const MULTISIG_MAX_PUBKEYS: usize = 15;

/// Worst-case redeem script: OP_m | (len-byte | pubkey) * n | OP_n | OP_CHECKMULTISIG
const SCRIPT_MAX_LEN: usize = 1 + MULTISIG_MAX_PUBKEYS * (1 + PUBKEY_LEN) + 2;

/// Encode a small integer (1..=16) as the OP_1..OP_16 opcode (0x51..0x60).
#[inline]
fn op_n(value: u8) -> u8 {
    0x50 + value
}

/// Compute the Hash160 of the P2SH multisig redeem script for the ordered key
/// set formed by splicing `device_pubkey` into `cosigner_keys` at `device_index`.
///
/// `cosigner_keys` is the concatenation of the (n-1) compressed cosigner public
/// keys, in order, excluding the device's own slot.
pub fn multisig_p2sh_hash160(
    device_pubkey: &[u8],
    cosigner_keys: &[u8],
    device_index: usize,
    num_required: usize,
) -> Result<[u8; HASH160_LEN], ParserError> {
    if device_pubkey.len() != PUBKEY_LEN {
        return Err(ParserError::ValueOutOfRange);
    }
    if cosigner_keys.len() % PUBKEY_LEN != 0 {
        return Err(ParserError::ValueOutOfRange);
    }

    let num_cosigners = cosigner_keys.len() / PUBKEY_LEN;
    let num_pubkeys = num_cosigners + 1;

    if num_pubkeys == 0 || num_pubkeys > MULTISIG_MAX_PUBKEYS {
        return Err(ParserError::ValueOutOfRange);
    }
    if num_required < 1 || num_required > num_pubkeys {
        return Err(ParserError::ValueOutOfRange);
    }
    if device_index >= num_pubkeys {
        return Err(ParserError::ValueOutOfRange);
    }

    // Build the redeem script.
    let mut script = [0u8; SCRIPT_MAX_LEN];
    let mut off = 0usize;

    script[off] = op_n(num_required as u8); // OP_m
    off += 1;

    let mut cosigner_i = 0usize;
    for i in 0..num_pubkeys {
        script[off] = PUBKEY_LEN as u8; // push 33 bytes
        off += 1;

        let key = if i == device_index {
            device_pubkey
        } else {
            let start = cosigner_i * PUBKEY_LEN;
            cosigner_i += 1;
            &cosigner_keys[start..start + PUBKEY_LEN]
        };
        script[off..off + PUBKEY_LEN].copy_from_slice(key);
        off += PUBKEY_LEN;
    }

    script[off] = op_n(num_pubkeys as u8); // OP_n
    off += 1;
    script[off] = OP_CHECKMULTISIG;
    off += 1;

    // Hash160 = RIPEMD160(SHA256(script))
    let mut sha = [0u8; SHA256_LEN];
    sha256(&script[..off], &mut sha).map_err(|_| ParserError::UnexpectedError)?;

    let mut hash160 = [0u8; HASH160_LEN];
    ripemd160(&sha, &mut hash160).map_err(|_| ParserError::UnexpectedError)?;

    Ok(hash160)
}

/// Full pipeline: ordered key set -> redeem-script Hash160 -> c32check address.
pub fn multisig_c32_address(
    device_pubkey: &[u8],
    cosigner_keys: &[u8],
    device_index: usize,
    num_required: usize,
    version: u8,
) -> Result<ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
    let hash160 = multisig_p2sh_hash160(device_pubkey, cosigner_keys, device_index, num_required)?;
    c32_address(version, &hash160)
}

/// C entry point. Writes the c32-encoded multisig address into `output` and
/// returns its length, or 0 on any error.
///
/// `cosigner_keys` points to `num_cosigners * 33` bytes (may be null when
/// `num_cosigners == 0`); the device's own key is spliced in at `device_index`.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn rs_multisig_c32_address(
    device_pubkey: *const u8,
    cosigner_keys: *const u8,
    num_cosigners: u8,
    device_index: u8,
    num_required: u8,
    version: u8,
    output: *mut u8,
    outLen: u16,
) -> u16 {
    if device_pubkey.is_null() || output.is_null() {
        return 0;
    }

    unsafe {
        let device = core::slice::from_raw_parts(device_pubkey, PUBKEY_LEN);

        let cosigners: &[u8] = if num_cosigners == 0 {
            &[]
        } else {
            if cosigner_keys.is_null() {
                return 0;
            }
            core::slice::from_raw_parts(cosigner_keys, num_cosigners as usize * PUBKEY_LEN)
        };

        match multisig_c32_address(
            device,
            cosigners,
            device_index as usize,
            num_required as usize,
            version,
        ) {
            Ok(addr) => {
                let len = addr.len();
                if (outLen as usize) < len {
                    return 0;
                }
                output.write_bytes(0, outLen as usize);
                output.copy_from_nonoverlapping(addr.as_ptr(), len);
                len as u16
            }
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::prelude::v1::*;

    // Valid compressed secp256k1 public keys used as fixed test cosigners.
    const A: &str = "03c00170321c5ce931d3201927ff6b1993c350f72af5483b9d75e8505ef10aed8c";
    const B: &str = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
    const C: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // secp256k1 G
    const D: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"; // 2*G

    // Reference vectors produced with the reference SDK:
    //   sc = @stacks/transactions.createMultiSigSpendingCondition(AddressHashMode.P2SH, m, orderedKeys, 0, 0)
    //   address = c32check.c32address(version, sc.signer)
    // `orderedKeys` is the device key spliced into the cosigners at `device_index`.
    struct Vector {
        device: &'static str,
        cosigners: &'static [&'static str],
        device_index: usize,
        num_required: usize,
        version: u8,
        hash160: &'static str,
        address: &'static str,
    }

    const VECTORS: &[Vector] = &[
        // 2-of-3 mainnet, ordered [A, C, B]
        Vector {
            device: C,
            cosigners: &[A, B],
            device_index: 1,
            num_required: 2,
            version: 20,
            hash160: "b7dd3b77e18712844f37d0f4e6e3604744ff1a5b",
            address: "SM2VXTEVQW63H512F6Z8F9SQ3C13M9ZRTBEBFAB0M",
        },
        // 1-of-2 testnet, ordered [C, A]
        Vector {
            device: C,
            cosigners: &[A],
            device_index: 0,
            num_required: 1,
            version: 21,
            hash160: "9a46656e4ec85f53e55029132c2074d33802befc",
            address: "SN2D4CSBE9V45YMZ5A0MH6B10EK9KG0NYZG6Y8NX4",
        },
        // 3-of-3 mainnet, ordered [A, B, C] (device last)
        Vector {
            device: C,
            cosigners: &[A, B],
            device_index: 2,
            num_required: 3,
            version: 20,
            hash160: "014c48498cc3023b065cd665197b6f2a9078f6ec",
            address: "SMMRJ29HK1G4ER6BKB6A6BVDWN90Y7PXJZFTK8G",
        },
        // 2-of-2 mainnet, ordered [D, A] (device first)
        Vector {
            device: D,
            cosigners: &[A],
            device_index: 0,
            num_required: 2,
            version: 20,
            hash160: "3525047edc070890b72c2439b1409c14962e5f4d",
            address: "SMTJA13YVG3GH45Q5GJ3KCA0KGA9CBJZ9P130TEH",
        },
        // 1-of-1 mainnet, ordered [C] (no cosigners)
        Vector {
            device: C,
            cosigners: &[],
            device_index: 0,
            num_required: 1,
            version: 20,
            hash160: "83eebb7d79aa1d388e3b0ac65b98ac580c4da01a",
            address: "SM21YXEVXF6N1TE4E7C5CCPWRNHC0RKD03BYFWSY4",
        },
        // Same keys/order as the first vector but testnet -> different address
        Vector {
            device: C,
            cosigners: &[A, B],
            device_index: 1,
            num_required: 2,
            version: 21,
            hash160: "b7dd3b77e18712844f37d0f4e6e3604744ff1a5b",
            address: "SN2VXTEVQW63H512F6Z8F9SQ3C13M9ZRTBCCMR3WN",
        },
    ];

    fn concat_keys(keys: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for k in keys {
            out.extend_from_slice(&hex::decode(k).unwrap());
        }
        out
    }

    #[test]
    fn multisig_address_reference_vectors() {
        for v in VECTORS {
            let device = hex::decode(v.device).unwrap();
            let cosigners = concat_keys(v.cosigners);

            let hash = multisig_p2sh_hash160(&device, &cosigners, v.device_index, v.num_required).unwrap();
            assert_eq!(
                hex::encode(hash),
                v.hash160,
                "hash160 mismatch for {}",
                v.address
            );

            let addr = multisig_c32_address(&device, &cosigners, v.device_index, v.num_required, v.version).unwrap();
            assert_eq!(
                std::str::from_utf8(&addr).unwrap(),
                v.address,
                "address mismatch for {}",
                v.address
            );
        }
    }

    // 8-of-15 mainnet, device at index 7. Reference produced with
    // @stacks/transactions.createMultiSigSpendingCondition(P2SH, 8, orderedKeys, 0, 0),
    // orderedKeys = compressed pubkeys for private keys 1..=15.
    #[test]
    fn multisig_address_15_keys() {
        let device = hex::decode("022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01").unwrap();
        // The 14 cosigner keys (private keys 1..=7 and 9..=15), device slot omitted.
        let cosigners = hex::decode(concat!(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
            "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
            "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
            "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
            "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
            "03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
            "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
            "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4",
            "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
        ))
        .unwrap();

        let hash = multisig_p2sh_hash160(&device, &cosigners, 7, 8).unwrap();
        assert_eq!(hex::encode(hash), "0d938bca9aea68afbe76b74fe8cbc609d159986b");

        let addr = multisig_c32_address(&device, &cosigners, 7, 8, 20).unwrap();
        assert_eq!(std::str::from_utf8(&addr).unwrap(), "SM6S72YAKBN6HBXYETVMZT6BRR4X2PCRDFXAD26S");
    }

    #[test]
    fn rejects_invalid_parameters() {
        let device = hex::decode(C).unwrap();
        let one = concat_keys(&[A]); // n = 2

        // threshold above n
        assert!(multisig_p2sh_hash160(&device, &one, 0, 3).is_err());
        // threshold zero
        assert!(multisig_p2sh_hash160(&device, &one, 0, 0).is_err());
        // device index out of range
        assert!(multisig_p2sh_hash160(&device, &one, 2, 1).is_err());
        // too many keys
        let many = concat_keys(&[A; 15]); // n = 16 > MAX (15)
        assert!(multisig_p2sh_hash160(&device, &many, 0, 1).is_err());
        // malformed device key
        assert!(multisig_p2sh_hash160(&[0u8; 10], &one, 0, 1).is_err());
        // malformed cosigner buffer (not a multiple of PUBKEY_LEN)
        assert!(multisig_p2sh_hash160(&device, &[0u8; 20], 0, 1).is_err());
    }
}
