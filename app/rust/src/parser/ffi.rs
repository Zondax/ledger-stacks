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

use crate::parser::{
    parser_common::TransactionVersion, transaction::*, transaction_auth::TransactionAuth,
    transaction_payload::TransactionPayload,
};

#[inline(never)]
fn header_and_auth(
    data: &[u8],
) -> Result<(&[u8], TransactionVersion, u32, TransactionAuth), ParserError> {
    let header = match Transaction::get_header(data) {
        Ok(h) => h,
        Err(_e) => return Err(ParserError::parser_unexpected_value),
    };
    let auth = match Transaction::get_auth(header.0) {
        Ok(h) => h,
        Err(_e) => return Err(ParserError::parser_invalid_auth_type),
    };
    Ok((auth.0, (header.1).0, (header.1).1, auth.1))
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn _read(context: *const parser_context_t, parser_state: *mut parse_tx_t) -> u32 {
    unsafe {
        let data = core::slice::from_raw_parts((*context).buffer, (*context).bufferLen as _);
        let (raw, version, chain_id, auth) = match header_and_auth(data) {
            Ok(res) => res,
            Err(e) => return e as u32,
        };
        let modes = match Transaction::get_modes(raw) {
            Ok(h) => h,
            Err(_e) => return ParserError::parser_invalid_post_condition as u32,
        };
        let (raw_conditions, conditions) = match Transaction::post_conditions(modes.0) {
            Ok(h) => h,
            Err(_e) => return ParserError::parser_invalid_post_condition as u32,
        };
        let (_raw_payload, payload) = match Transaction::get_payload(raw_conditions) {
            Ok(h) => h,
            Err(_e) => return ParserError::parser_invalid_transaction_payload as u32,
        };

        // Note that if a transaction contains a token-transfer payload,
        // it MUST have only a standard authorization field. It cannot be sponsored.
        if payload.is_token_transfer_payload() && !auth.is_standard_auth() {
            return ParserError::parser_invalid_transaction_payload as u32;
        }
        let transaction = Transaction {
            version,
            chain_id,
            transaction_auth: auth,
            anchor_mode: (modes.1).0,
            post_condition_mode: (modes.1).1,
            post_conditions: conditions,
            payload,
        };
        let len = core::mem::size_of::<Transaction>();
        let tx = &transaction as *const _ as *const u8;
        core::ptr::copy_nonoverlapping(tx, (*parser_state).state, len);
        ParserError::parser_ok as u32
    }
}

#[no_mangle]
pub extern "C" fn _validate(_ctx: *const parser_context_t, _tx_t: *const parse_tx_t) -> u32 {
    // TODO
    ParserError::parser_ok as u32
}

#[no_mangle]
pub extern "C" fn _getNumItems(_ctx: *const parser_context_t, tx_t: *const parse_tx_t) -> u8 {
    unsafe {
        if tx_t.is_null() || (*tx_t).state.is_null() {
            return 0;
        }
        if let Some(tx) = ((*tx_t).state as *const Transaction).as_ref() {
            return tx.num_items();
        }
        0
    }
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
    unsafe {
        *pageCount = 0u8;
        let key = core::slice::from_raw_parts_mut(outKey as *mut u8, outKeyLen as usize);
        let value = core::slice::from_raw_parts_mut(outValue as *mut u8, outValueLen as usize);
        if tx_t.is_null() || (*tx_t).state.is_null() {
            return ParserError::parser_context_mismatch as _;
        }
        if let Some(tx) = ((*tx_t).state as *const u8 as *const Transaction).as_ref() {
            return match tx.get_item(displayIdx, key, value, pageIdx) {
                Ok(page) => {
                    *pageCount = page;
                    ParserError::parser_ok as _
                }
                Err(e) => e as _,
            };
        }
        ParserError::parser_context_mismatch as _
    }
}
