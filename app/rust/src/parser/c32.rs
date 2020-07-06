use arrayvec::ArrayVec;
use sha2::Digest;
use sha2::Sha256;

use crate::parser::parser_common::{ParserError, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN};

pub const C32_ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 22;
pub const C32_ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 20;
pub const C32_ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 26;
pub const C32_ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 21;

const C32_CHARACTERS: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn rs_c32_address(
    input: *const u8,
    version: u8,
    output: *mut u8,
    outLen: u16,
) -> u16 {
    if input.is_null() | output.is_null() {
        return 0;
    }
    unsafe {
        let raw =
            // We expect hash160 raw data
            core::slice::from_raw_parts(input, HASH160_LEN);
        if let Ok(res) = c32_address(version, raw) {
            let encoded_len = res.len();
            if (outLen as usize) < encoded_len {
                return 0;
            }
            // Initialize our output with null bytes
            output.write_bytes(0, outLen as usize);

            output.copy_from_nonoverlapping(res.as_ptr(), encoded_len);
            return encoded_len as u16;
        }
    }
    0
}

fn double_sha256_checksum(data: &[u8]) -> [u8; 4] {
    let mut sha2 = Sha256::new();
    let mut tmp = [0u8; 32];
    let mut tmp_2 = [0u8; 32];
    let mut sum = [0u8; 4];

    sha2.update(data);
    tmp.copy_from_slice(sha2.finalize().as_slice());

    let mut sha2_2 = Sha256::new();
    sha2_2.update(&tmp);
    tmp_2.copy_from_slice(sha2_2.finalize().as_slice());

    sum.copy_from_slice(&tmp_2[0..4]);
    sum
}

fn c32_encode(input_bytes: &[u8]) -> ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]> {
    let c32_chars: &[u8] = C32_CHARACTERS.as_bytes();

    let mut result = ArrayVec::<[_; C32_ENCODED_ADDRS_LENGTH]>::new();
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(c32_chars[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(c32_chars[c32_value as usize]);
            carry_bits -= 5;
            carry >>= 5;
        }
    }

    if carry_bits > 0 {
        result.push(c32_chars[carry as usize]);
    }

    // remove leading zeros from c32 encoding
    while let Some(v) = result.pop() {
        if v != c32_chars[0] {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            result.push(c32_chars[0]);
        } else {
            break;
        }
    }
    let result: ArrayVec<[_; C32_ENCODED_ADDRS_LENGTH]> = result.drain(..).rev().collect();
    result
}

fn c32_check_encode(
    version: u8,
    data: &[u8],
) -> Result<ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
    if version >= 32 {
        return Err(ParserError::parser_invalid_address_version);
    }

    let mut check_data = [0u8; 21];
    check_data[0] = version;
    check_data[1..].copy_from_slice(data);
    let checksum = double_sha256_checksum(&check_data);

    let mut encoding_data = [0u8; 24]; // data.to_vec();
    encoding_data[..20].copy_from_slice(data);
    encoding_data[20..].copy_from_slice(&checksum);

    // working with ascii strings is awful.
    let mut c32_string = c32_encode(&encoding_data);
    let version_char = C32_CHARACTERS.as_bytes()[version as usize];
    c32_string.insert(0, version_char);

    Ok(c32_string)
}

pub fn c32_address(
    version: u8,
    data: &[u8],
) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
    let mut c32_string = c32_check_encode(version, data)?;
    c32_string.insert(0, b'S');
    Ok(c32_string)
}
