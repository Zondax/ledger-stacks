#![allow(clippy::missing_safety_doc)]
use crate::parser::{parser_common::ParserError, transaction::Transaction};
//use crate::{bolos::c_zemu_log_stack, check_canary, zxformat};
use core::mem::ManuallyDrop;

// We chose an union as later new
// message types may be added
// safety: this is memory allocated in C and last the application lifetime
// and is initialize once.
#[repr(C)]
pub union Message<'a> {
    // leave room for another structured data
    bstr: ManuallyDrop<ByteString<'a>>,
}

impl<'a> Message<'a> {
    pub fn is_message(data: &'a [u8]) -> bool {
        ByteString::is_byte_string(data)
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        unsafe { self.bstr.num_items() }
    }
    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        unsafe { self.bstr.read(data) }
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
#[derive(Debug, Clone, PartialEq)]
pub struct ByteString<'a> {
    data: &'a [u8],
}

impl<'a> ByteString<'a> {
    pub fn is_byte_string(data: &'a [u8]) -> bool {
        // check if data is a possible message
        // Only parsing will tell if it is true
        let msg_bytes = "\x19Stacks Signed Message:".as_bytes();
        data.len() >= msg_bytes.len() && &data[..msg_bytes.len()] == msg_bytes
    }

    pub fn read(&mut self, _data: &'a [u8]) -> Result<(), ParserError> {
        todo!()
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        todo!()
    }

    pub fn get_item(
        &mut self,
        _display_idx: u8,
        _out_key: &mut [u8],
        _out_value: &mut [u8],
        _page_idx: u8,
    ) -> Result<u8, ParserError> {
        todo!()
    }
}
