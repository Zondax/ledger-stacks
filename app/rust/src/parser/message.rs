#![allow(clippy::missing_safety_doc)]
use crate::parser::{parser_common::ParserError, transaction::Transaction};
use crate::{
    bolos::c_zemu_log_stack,
    check_canary,
    zxformat::{pageString, Writer},
};
use core::fmt::Write;

use core::mem::ManuallyDrop;

// The lenght of \x19Stacks Signed Message:
const BYTE_STRING_HEADER_LEN: usize = "\x19Stacks Signed Message:\n".as_bytes().len();

// The max number of characters we are going to show on the screen
const MAX_CHARS_TO_SHOW_FROM_MSG: usize = 60;

// We chose an union as later new
// message types may be added
// safety: this is memory allocated in C and last the application lifetime
// and is initialized once. It is the C-side responsability to free the memory. that's why
// we use repr(C) key word
#[repr(C)]
pub union Message<'a> {
    // leave room for another structured data
    bstr: ByteString<'a>,
}

impl<'a> Message<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        let byte_str = ByteString::from_bytes(data)?;
        Ok(Self { bstr: byte_str })
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        let bstr = ByteString::from_bytes(data)?;
        self.bstr = bstr;
        Ok(())
    }

    pub fn is_message(data: &'a [u8]) -> bool {
        ByteString::maybe_byte_string(data)
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        unsafe { self.bstr.num_items() }
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        unsafe {
            self.bstr
                .get_item(display_idx, out_key, out_value, page_idx)
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct ByteString<'a> {
    data: &'a [u8],
    at: usize,
    len: usize,
}

impl<'a> ByteString<'a> {
    pub fn maybe_byte_string(data: &'a [u8]) -> bool {
        Self::contain_header(data)
    }

    const fn header() -> &'static str {
        "\x19Stacks Signed Message:\n"
    }

    // Checks if the input data contain the byte_string heades at the first bytes
    fn contain_header(data: &[u8]) -> bool {
        //let msg_bytes = Self::header().as_bytes();
        let msg_bytes = "\x19Stacks Signed Message:\n".as_bytes();
        data.len() > BYTE_STRING_HEADER_LEN && &data[..BYTE_STRING_HEADER_LEN] == msg_bytes
    }

    fn msg_len(data: &'a [u8]) -> Result<(usize, usize), ParserError> {
        if data.is_empty() || !data.is_ascii() {
            return Err(ParserError::parser_invalid_bytestr_message);
        }
        let mut digit_count = 0usize;
        let mut len;
        for (index, c) in data.iter().enumerate() {
            if (*c as char).is_ascii_digit() {
                digit_count += 1;

                len = lexical_core::parse::<usize>(&data[..=index])
                    .map_err(|_| ParserError::parser_value_out_of_range)?;

                let data_len = data.len() - digit_count;

                // no trailing zeros
                if len == 0 && data_len > 1 {
                    return Err(ParserError::parser_invalid_bytestr_message);
                }

                if len == data_len {
                    return Ok((digit_count, len));
                }
            } else {
                break;
            }
        }
        Err(ParserError::parser_invalid_bytestr_message)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if !Self::contain_header(data) {
            return Err(ParserError::parser_invalid_bytestr_message);
        }
        let (at, len) = Self::msg_len(&data[BYTE_STRING_HEADER_LEN..])?;
        let at = BYTE_STRING_HEADER_LEN + at;
        Ok(Self { data, at, len })
    }

    pub const fn num_items(&self) -> Result<u8, ParserError> {
        //One ByteString message to show at least partially
        Ok(1)
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

            let len = if self.len > MAX_CHARS_TO_SHOW_FROM_MSG {
                MAX_CHARS_TO_SHOW_FROM_MSG
            } else {
                self.len
            } + self.at;

            pageString(out_value, &self.data[self.at..len], page_idx)
        } else {
            Err(ParserError::parser_display_idx_out_of_range)
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::string::String;

    use super::*;

    fn built_message(len: usize, data: &str) -> String {
        format!("\x19Stacks Signed Message:\n{}{}", len, data)
    }

    #[test]
    fn test_non_ascii_byte_string() {
        let no_ascii = "Test-love: ❤️";
        let no_ascii = built_message(no_ascii.len(), no_ascii);
        let msg = ByteString::from_bytes(no_ascii.as_bytes());
        assert!(msg.is_err());
    }

    #[test]
    fn test_valid_byte_string() {
        let data = "byte_string_valid";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(m.as_bytes());
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(&msg.data[msg.at..], data.as_bytes());
    }

    #[test]
    fn test_valid_starts_with_number() {
        let data = "1_byte_string_valid";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(m.as_bytes());
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(&msg.data[msg.at..], data.as_bytes());
    }

    #[test]
    fn test_empty_byte_string() {
        let data = "";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(m.as_bytes());
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(&msg.data[msg.at..], data.as_bytes());
    }

    #[test]
    fn test_wrong_len_byte_string() {
        let m = "byte_string_valid";
        let m = built_message(34, m);
        let msg = ByteString::from_bytes(m.as_bytes());
        assert!(msg.is_err());
    }

    #[test]
    fn test_only_text() {
        let msg = ByteString::from_bytes("\x19Stacks Signed Message:\nHello_world".as_bytes());
        assert!(msg.is_err());
    }

    #[test]
    fn test_only_header() {
        let msg = ByteString::from_bytes("\x19Stacks Signed Message:\n".as_bytes());
        assert!(msg.is_err());
    }
}
