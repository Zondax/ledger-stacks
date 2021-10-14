use crate::parser::{parser_common::ParserError, transaction::Transaction, Message};
use crate::{bolos::c_zemu_log_stack, check_canary};
use nom::error::ErrorKind;

use core::mem::ManuallyDrop;

// safety: this is memory allocated in C and last the application lifetime
// and is initialized once which means that once the object is initialized with an especific
// union variant such variant wont be changed.
#[repr(C)]
pub union ParsedObj<'a> {
    tx: ManuallyDrop<Transaction<'a>>,
    msg: ManuallyDrop<Message<'a>>,
}

impl<'a> ParsedObj<'a> {
    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        if data.len() == 0 {
            return Err(ParserError::parser_no_data);
        }

        unsafe {
            if !Message::is_message(data) {
                (&mut *self.tx).read(data)
            } else {
                (&mut *self.msg).read(data)
            }
        }
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        unsafe {
            match self {
                Self { tx } => tx.num_items(),
                Self { msg } => msg.num_items(),
            }
        }
    }

    pub fn get_item(
        &mut self,
        displayIdx: u8,
        outKey: *mut i8,
        outKeyLen: u16,
        outValue: *mut i8,
        outValueLen: u16,
        pageIdx: u8,
    ) -> Result<u8, ParserError> {
        let (key, value) = unsafe {
            let key = core::slice::from_raw_parts_mut(outKey as *mut u8, outKeyLen as usize);
            let value = core::slice::from_raw_parts_mut(outValue as *mut u8, outValueLen as usize);
            (key, value)
        };
        unsafe {
            match self {
                Self { ref mut tx } => (&mut *tx).get_item(displayIdx, key, value, pageIdx),
                Self { ref mut msg } => (&mut *msg).get_item(displayIdx, key, value, pageIdx),
            }
        }
    }

    pub fn is_transaction(&self) -> bool {
        unsafe { matches!(self, &Self { ref tx }) }
    }
    // For now we support only ByteString messages
    // but this later new data types could be to added
    pub fn is_message(&self) -> bool {
        unsafe { matches!(self, &Self { ref msg }) }
    }

    #[inline(always)]
    pub fn transaction(&mut self) -> Option<&mut Transaction<'a>> {
        unsafe {
            match self {
                Self { ref mut tx } => Some(tx),
                _ => None,
            }
        }
    }

    pub fn message(&mut self) -> Option<&mut Message<'a>> {
        unsafe {
            match self {
                Self { ref mut msg } => Some(msg),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod test {}
