#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]
use crate::parser::{parser_common::ParserError, transaction::Transaction, Message};
use crate::{bolos::c_zemu_log_stack, check_canary};
use nom::error::ErrorKind;

use core::mem::ManuallyDrop;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    Transaction,
    Message,
}

// safety: this is memory allocated in C and last the application lifetime
// and is initialized once which means that once the object is initialized with an especific
// union variant such variant wont be changed.
#[repr(C)]
pub union Obj<'a> {
    tx: ManuallyDrop<Transaction<'a>>,
    msg: ManuallyDrop<Message<'a>>,
}

pub struct ParsedObj<'a> {
    tag: Tag,
    obj: Obj<'a>,
}

impl<'a> ParsedObj<'a> {
    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::parser_no_data);
        }

        self.tag = Tag::Transaction;

        unsafe {
            if !Message::is_message(data) {
                self.obj.read_tx(data)
            } else {
                self.tag = Tag::Message;
                self.obj.read_msg(data)
            }
        }
    }

    pub fn num_items(&mut self) -> Result<u8, ParserError> {
        unsafe {
            match self.tag {
                Tag::Transaction => self.obj.transaction().num_items(),
                Tag::Message => self.obj.message().num_items(),
            }
        }
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        key: &mut [u8],
        value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        unsafe {
            match self.tag {
                Tag::Transaction => {
                    self.obj
                        .transaction()
                        .get_item(display_idx, key, value, page_idx)
                }
                Tag::Message => self
                    .obj
                    .message()
                    .get_item(display_idx, key, value, page_idx),
            }
        }
    }

    pub fn is_transaction(&self) -> bool {
        matches!(self.tag, Tag::Transaction)
    }
    // For now we support only ByteString messages
    // but this later new data types could be to added
    pub fn is_message(&self) -> bool {
        matches!(self.tag, Tag::Message)
    }

    #[inline(always)]
    pub fn transaction(&mut self) -> Option<&mut Transaction<'a>> {
        unsafe {
            if self.tag == Tag::Transaction {
                Some(self.obj.transaction())
            } else {
                None
            }
        }
    }

    pub fn message(&mut self) -> Option<&mut Message<'a>> {
        unsafe {
            if self.tag == Tag::Message {
                Some(self.obj.message())
            } else {
                None
            }
        }
    }
}

impl<'a> Obj<'a> {
    pub unsafe fn read_tx(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.tx).read(data)
    }

    pub unsafe fn read_msg(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.msg).read(data)
    }

    #[inline(always)]
    pub unsafe fn transaction(&mut self) -> &mut Transaction<'a> {
        &mut *self.tx
    }

    pub unsafe fn message(&mut self) -> &mut Message<'a> {
        &mut *self.msg
    }
}

#[cfg(test)]
mod test {}
