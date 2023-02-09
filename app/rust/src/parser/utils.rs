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
    let (rem, prefix) = le_u8(input)?;

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

pub trait ApduPanic: Sized {
    type Item;

    fn apdu_unwrap(self) -> Self::Item;

    fn apdu_expect(self, s: &str) -> Self::Item;
}

impl<T, E> ApduPanic for Result<T, E> {
    type Item = T;

    #[inline]
    fn apdu_unwrap(self) -> Self::Item {
        match self {
            Ok(t) => t,
            Err(_) => panic!(),
        }
    }

    #[inline]
    fn apdu_expect(self, _: &str) -> Self::Item {
        match self {
            Ok(t) => t,
            Err(_) => panic!(),
        }
    }
}

impl<T> ApduPanic for Option<T> {
    type Item = T;

    #[inline]
    fn apdu_unwrap(self) -> Self::Item {
        match self {
            Some(t) => t,
            _ => panic!(),
        }
    }

    #[inline]
    fn apdu_expect(self, _: &str) -> Self::Item {
        match self {
            Some(t) => t,
            _ => panic!(),
        }
    }
}








