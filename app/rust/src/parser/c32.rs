use crate::parser::{
    error::ParserError,
    parser_common::{C32_ENCODED_ADDRS_LENGTH, HASH160_LEN},
};
use arrayvec::ArrayVec;

#[cfg(not(any(test, fuzzing)))]
use crate::bolos::sha256;

use crate::bolos::SHA256_LEN;

#[cfg(any(test, fuzzing))]
use sha2::Digest;

#[cfg(any(test, fuzzing))]
use sha2::Sha256;

pub const C32_ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 22;
pub const C32_ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 20;
pub const C32_ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 26;
pub const C32_ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 21;

const C32_CHARACTERS: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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

#[cfg(any(test, fuzzing))]
fn double_sha256_checksum(data: &mut [u8; SHA256_LEN]) {
    let digest = Sha256::digest(&data[..21]);
    data.copy_from_slice(digest.as_slice());
    let sha2_2 = Sha256::digest(&data[..]);
    data[20..24].copy_from_slice(&sha2_2.as_slice()[..4]);
}

#[cfg(not(any(test, fuzzing)))]
fn double_sha256_checksum(data: &mut [u8; SHA256_LEN]) {
    let mut output = [0u8; SHA256_LEN];
    // safe to unwrap as we are passing the right len
    sha256(&data[..21], &mut output[..]).unwrap();
    data.copy_from_slice(output.as_ref());
    // safe to unwrap as we are passing the right len
    sha256(&data[..], &mut output).unwrap();
    data[20..24].copy_from_slice(&output[..4])
}

#[inline(never)]
fn c32_encode(input_bytes: &[u8], result: &mut ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>) {
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(C32_CHARACTERS[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(C32_CHARACTERS[c32_value as usize]);
            carry_bits -= 5;
            carry >>= 5;
        }
    }

    if carry_bits > 0 {
        result.push(C32_CHARACTERS[carry as usize]);
    }

    // remove leading zeros from c32 encoding
    while let Some(v) = result.pop() {
        if v != C32_CHARACTERS[0] {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            result.push(C32_CHARACTERS[0]);
        } else {
            break;
        }
    }
    result.reverse();
}

#[inline(never)]
fn c32_check_encode(
    version: u8,
    data: &[u8],
    c32_string: &mut ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>,
) -> Result<(), ParserError> {
    if version >= 32 {
        return Err(ParserError::parser_invalid_address_version);
    }

    // check_data will contain our initial version + signature hash
    // but will also be used as a temp buffer in the checksum function
    let mut check_data = [0u8; 32];
    check_data[0] = version;
    check_data[1..21].copy_from_slice(data);
    double_sha256_checksum(&mut check_data);

    // the first 20 bytes correspond to our initial signature hash
    // the next 4-bytes were filled by the double_sha256_checksum
    check_data[..20].copy_from_slice(data);

    // here we use only the 24-bytes
    c32_encode(&check_data[..24], c32_string);
    let version_char = C32_CHARACTERS[version as usize];
    c32_string.insert(0, version_char);
    Ok(())
}

//#[inline(never)]
pub fn c32_address(
    version: u8,
    data: &[u8],
) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
    let mut c32_string = ArrayVec::<[_; C32_ENCODED_ADDRS_LENGTH]>::new();
    c32_check_encode(version, data, &mut c32_string)?;
    c32_string.insert(0, b'S');
    Ok(c32_string)
}
