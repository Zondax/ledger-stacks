#![allow(clippy::missing_safety_doc)]
use super::{error::ParserError, read_varint};
use crate::zxformat::{pageString, Writer};
use core::fmt::Write;
use nom::bytes::complete::take;

// The lenght of \x17Stacks Signed Message:
const BYTE_STRING_HEADER_LEN: usize = "\x17Stacks Signed Message:\n".as_bytes().len();
// Truncates an ascii
// message to around this size, as we need to change special characters
// like /t or /r with spaces.
const MAX_ASCII_LEN: usize = 270;

#[repr(C)]
pub struct Message<'a>(ByteString<'a>);

impl<'a> Message<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        ByteString::from_bytes(data).map(Self)
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        ByteString::from_bytes(data).map(|msg| {
            self.0 = msg;
        })
    }

    pub fn is_message(data: &'a [u8]) -> bool {
        ByteString::is_msg(data)
    }

    pub fn num_items(&self) -> u8 {
        self.0.num_items()
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        self.0.get_item(display_idx, out_key, out_value, page_idx)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ByteString<'a>(&'a [u8]);

impl<'a> ByteString<'a> {
    pub fn is_msg(data: &'a [u8]) -> bool {
        Self::contain_header(data)
    }

    // Checks if the input data contain the byte_string heades at the first bytes
    fn contain_header(data: &[u8]) -> bool {
        let header = "\x17Stacks Signed Message:\n".as_bytes();
        data.len() > BYTE_STRING_HEADER_LEN && &data[..BYTE_STRING_HEADER_LEN] == header
    }

    // returns the message content
    fn get_msg(data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        if data.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        let (rem, len) = read_varint(data).map_err(|_| ParserError::InvalidBytestrMessage)?;

        let (_, message_content) = take::<_, _, ParserError>(len as usize)(rem)
            .map_err(|_| ParserError::InvalidBytestrMessage)?;

        if !message_content.is_ascii() {
            return Err(ParserError::InvalidBytestrMessage);
        }

        Ok(message_content)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if !Self::contain_header(data) {
            return Err(ParserError::InvalidBytestrMessage);
        }
        let message = Self::get_msg(&data[BYTE_STRING_HEADER_LEN..])?;
        Ok(Self(message))
    }

    pub const fn num_items(&self) -> u8 {
        //One ByteString message to show at least partially
        1
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx != 0 {
            return Err(ParserError::DisplayIdxOutOfRange);
        }

        let mut writer_key = Writer::new(out_key);

        let mut msg = [0; MAX_ASCII_LEN + 3];
        let suffix = [b'.'; 3];

        // look for special characters [\b..=\r]
        // and replace them with space b' '
        let msg_iter = self.0.iter().map(|c| {
            if (*c >= 0x08) && (*c <= b'\r') {
                b' '
            } else {
                *c
            }
        });

        let mut copy_len = if self.0.len() > MAX_ASCII_LEN {
            let m = msg
                .get_mut(MAX_ASCII_LEN..MAX_ASCII_LEN + suffix.len())
                .ok_or(ParserError::UnexpectedBufferEnd)?;
            m.copy_from_slice(&suffix[..]);
            MAX_ASCII_LEN
        } else {
            self.0.len()
        };

        msg.iter_mut()
            .take(copy_len)
            .zip(msg_iter)
            .for_each(|(r, m)| *r = m);

        if copy_len >= MAX_ASCII_LEN {
            copy_len += suffix.len()
        }

        writer_key
            .write_str("Sign Message")
            .map_err(|_| ParserError::UnexpectedBufferEnd)?;

        pageString(out_value, &msg[..copy_len], page_idx)
    }
}

#[cfg(test)]
mod test {
    use std::prelude::v1::*;

    use super::*;

    fn built_message(len: usize, data: &str) -> Vec<u8> {
        let header = "\x17Stacks Signed Message:\n".as_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(header);
        vec.push(len as u8);
        vec.extend_from_slice(data.as_bytes());
        vec
    }

    #[test]
    fn test_non_ascii_byte_string() {
        let no_ascii = "Test-love: ❤️";
        let no_ascii = built_message(no_ascii.len(), no_ascii);
        let msg = ByteString::from_bytes(&no_ascii);
        assert!(msg.is_err());
    }

    #[test]
    fn test_valid_byte_string() {
        let data = "byte_string_valid";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.0, data.as_bytes());
    }

    #[test]
    fn test_valid_starts_with_number() {
        let data = "1_byte_string_valid";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.0, data.as_bytes());
    }

    #[test]
    fn test_empty_byte_string() {
        let data = "";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.0, data.as_bytes());
    }

    #[test]
    fn test_wrong_len_byte_string() {
        let m = "byte_string_valid";
        let m = built_message(34, m);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_err());
    }

    #[test]
    fn test_only_text() {
        let msg = ByteString::from_bytes("\x17Stacks Signed Message:\nHello_world".as_bytes());
        assert!(msg.is_err());
    }

    #[test]
    fn test_only_header() {
        let msg = ByteString::from_bytes("\x17Stacks Signed Message:\n".as_bytes());
        assert!(msg.is_err());
    }
}
