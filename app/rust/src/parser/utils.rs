use super::ParserError;
use nom::number::complete::{le_u16, le_u32, le_u64, le_u8};

const FD_PREFIX: u8 = 0xfd;
const FE_PREFIX: u8 = 0xfe;
const FF_PREFIX: u8 = 0xff;

// stick to the bitcoin spec
// refer to https://learnmeabitcoin.com/technical/varint
// for more detail
pub fn read_varint(input: &[u8]) -> Result<(&[u8], u64), nom::Err<ParserError>> {
    // read len prefix
    #[cfg(test)]
    std::println!("*bytes {:?}", input);
    let (rem, prefix) = le_u8(input)?;
    #[cfg(test)]
    std::println!("len {}", prefix);

    // check prefix
    match prefix {
        FD_PREFIX => {
            // the next 2-bytes are the next field len
            le_u16(rem).map(|(rem, len)| (rem, len as u64))
        }
        FE_PREFIX => {
            // the next 4-bytes are the next field len
            le_u32(rem).map(|(rem, len)| (rem, len as u64))
        }
        FF_PREFIX => {
            // the next 4-bytes are the next field len
            le_u64(rem)
        }
        // the prefix is the actual len
        _ => Ok((rem, prefix as _)),
    }
}
