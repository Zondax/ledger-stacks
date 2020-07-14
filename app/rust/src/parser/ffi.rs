#![allow(non_camel_case_types, non_snake_case)]
#![allow(clippy::cast_ptr_alignment)]

use crate::parser::{
    parser_common::ParserError, post_condition::TransactionPostCondition, transaction::Transaction,
};

// extern c function for formatting to fixed point number
extern "C" {
    pub fn fp_uint64_to_str(out: *mut i8, outLen: u16, value: u64, decimals: u8) -> u16;
}

#[repr(C)]
#[no_mangle]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u16,
    pub offset: u16,
}

#[repr(C)]
#[no_mangle]
pub struct parse_tx_t {
    state: *mut u8,
    len: u16,
}

fn transaction_from<'a>(tx: *mut parse_tx_t) -> Option<&'a mut Transaction<'a>> {
    unsafe { ((*tx).state as *const u8 as *mut Transaction).as_mut() }
}

#[no_mangle]
pub extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
    alloc_size: *mut u16,
) -> u32 {
    // Lets the caller know how much memory we need for allocating
    // our global state
    if alloc_size.is_null() {
        return ParserError::parser_no_memory_for_state as u32;
    }
    unsafe {
        *alloc_size = core::mem::size_of::<Transaction>() as u16;
    }
    parser_init_context(ctx, buffer, bufferSize) as u32
}

fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
) -> ParserError {
    unsafe {
        (*ctx).offset = 0;

        if bufferSize == 0 || buffer.is_null() {
            (*ctx).buffer = core::ptr::null_mut();
            (*ctx).bufferLen = 0;
            return ParserError::parser_init_context_empty;
        }

        (*ctx).buffer = buffer;
        (*ctx).bufferLen = bufferSize;
        ParserError::parser_ok
    }
}

#[no_mangle]
pub extern "C" fn _read(context: *const parser_context_t, parser_state: *mut parse_tx_t) -> u32 {
    let data = unsafe { core::slice::from_raw_parts((*context).buffer, (*context).bufferLen as _) };

    if let Some(tx) = transaction_from(parser_state) {
        match tx.read(data) {
            Ok(_) => ParserError::parser_ok as u32,
            Err(e) => e as u32,
        }
    } else {
        ParserError::parser_no_memory_for_state as u32
    }
}

#[no_mangle]
pub extern "C" fn _validate(_ctx: *const parser_context_t, tx_t: *const parse_tx_t) -> u32 {
     ParserError::parser_ok as u32

}

#[no_mangle]
pub extern "C" fn _getNumItems(_ctx: *const parser_context_t, tx_t: *const parse_tx_t) -> u8 {
    unsafe {
        if tx_t.is_null() || (*tx_t).state.is_null() {
            return 0;
        }
    }
    if let Some(tx) = transaction_from(tx_t as _) {
        return tx.num_items();
    }
    0
}

#[no_mangle]
pub extern "C" fn _getItem(
    _ctx: *const parser_context_t,
    displayIdx: u8,
    outKey: *mut i8,
    outKeyLen: u16,
    outValue: *mut i8,
    outValueLen: u16,
    pageIdx: u8,
    pageCount: *mut u8,
    tx_t: *const parse_tx_t,
) -> u32 {
    let (page_count, key, value) = unsafe {
        *pageCount = 0u8;
        let page_count = &mut *pageCount;
        let key = core::slice::from_raw_parts_mut(outKey as *mut u8, outKeyLen as usize);
        let value = core::slice::from_raw_parts_mut(outValue as *mut u8, outValueLen as usize);
        if tx_t.is_null() || (*tx_t).state.is_null() {
            return ParserError::parser_context_mismatch as _;
        }
        (page_count, key, value)
    };
    if let Some(tx) = transaction_from(tx_t as _) {
        return match tx.get_item(displayIdx, key, value, pageIdx) {
            Ok(page) => {
                *page_count = page;
                ParserError::parser_ok as _
            }
            Err(e) => e as _,
        };
    }
    ParserError::parser_context_mismatch as _
}
