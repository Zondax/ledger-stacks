#![allow(clippy::missing_safety_doc)]
use super::{error::ParserError, read_varint};
use crate::zxformat::{pageString, Writer};
use core::fmt::Write;
use nom::bytes::complete::take;

// The lenght of \x17Stacks Signed Message:
const BYTE_STRING_HEADER_LEN: usize = "\x17Stacks Signed Message:\n".as_bytes().len();

#[repr(C)]
pub enum Message<'a> {
    // leave room for another structured data
    ByteStr(ByteString<'a>),
}

impl<'a> Message<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        let byte_str = ByteString::from_bytes(data)?;
        Ok(Message::ByteStr(byte_str))
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        if ByteString::maybe_byte_string(data) {
            *self = Message::ByteStr(ByteString::from_bytes(data)?);
            Ok(())
        } else {
            Err(ParserError::parser_unexpected_type)
        }
    }

    pub fn is_message(data: &'a [u8]) -> bool {
        ByteString::maybe_byte_string(data)
    }

    pub fn num_items(&self) -> u8 {
        match self {
            Message::ByteStr(bstr) => bstr.num_items(),
        }
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        match self {
            Message::ByteStr(bstr) => bstr.get_item(display_idx, out_key, out_value, page_idx),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ByteString<'a>(&'a [u8]);

impl<'a> ByteString<'a> {
    pub fn maybe_byte_string(data: &'a [u8]) -> bool {
        Self::contain_header(data)
    }

    // Checks if the input data contain the byte_string heades at the first bytes
    fn contain_header(data: &[u8]) -> bool {
        let msg_bytes = "\x17Stacks Signed Message:\n".as_bytes();
        data.len() > BYTE_STRING_HEADER_LEN && &data[..BYTE_STRING_HEADER_LEN] == msg_bytes
    }

    // returns the message content
    fn get_msg(data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        if data.is_empty() || !data.is_ascii() {
            return Err(ParserError::parser_invalid_bytestr_message);
        }

        let (rem, len) =
            read_varint(data).map_err(|_| ParserError::parser_invalid_bytestr_message)?;
        let (_, message_content) = take::<_, _, ParserError>(len as usize)(rem)
            .map_err(|_| ParserError::parser_invalid_bytestr_message)?;

        Ok(message_content)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if !Self::contain_header(data) {
            return Err(ParserError::parser_invalid_bytestr_message);
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
        let mut writer_key = Writer::new(out_key);

        if display_idx == 0 {
            writer_key
                .write_str("Sign Message")
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;

            pageString(out_value, self.0, page_idx)
        } else {
            Err(ParserError::parser_display_idx_out_of_range)
        }
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
