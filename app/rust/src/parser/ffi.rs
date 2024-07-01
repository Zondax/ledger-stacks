#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]
#![allow(clippy::cast_ptr_alignment)]

use crate::parser::{error::ParserError, spending_condition::TransactionAuthField, ParsedObj, Tag};

// extern c function for formatting to fixed point number
extern "C" {
    pub fn fp_uint64_to_str(out: *mut i8, outLen: u16, value: u64, decimals: u8) -> u16;
}

#[repr(C)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u16,
    pub offset: u16,
}

#[repr(C)]
pub struct parse_tx_t {
    state: *mut u8,
    len: u16,
}

/// #Safety
/// Enough space was allocated to store a ParsedObj
unsafe fn parsed_obj_from_state<'a>(tx: *mut parse_tx_t) -> Option<&'a mut ParsedObj<'a>> {
    ((*tx).state as *const u8 as *mut ParsedObj).as_mut()
}

#[no_mangle]
pub unsafe extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
    alloc_size: *mut u16,
) -> u32 {
    // Lets the caller know how much memory we need for allocating
    // our global state
    if alloc_size.is_null() {
        return ParserError::NoMemoryForState as u32;
    }
    *alloc_size = core::mem::size_of::<ParsedObj>() as u16;
    parser_init_context(ctx, buffer, bufferSize) as u32
}

/// #Safety
/// Called after zb_allocate assign memory
/// to store the ParsedObj. This memory outlives
/// the parsed and is deallocated before signing
/// at such point the rust-parser is not used anymore
unsafe fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
) -> ParserError {
    (*ctx).offset = 0;

    if bufferSize == 0 || buffer.is_null() {
        (*ctx).buffer = core::ptr::null_mut();
        (*ctx).bufferLen = 0;
        return ParserError::InitContextEmpty;
    }

    (*ctx).buffer = buffer;
    (*ctx).bufferLen = bufferSize;
    ParserError::ParserOk
}

#[no_mangle]
pub unsafe extern "C" fn _read(
    context: *const parser_context_t,
    parser_state: *mut parse_tx_t,
) -> u32 {
    let data = core::slice::from_raw_parts((*context).buffer, (*context).bufferLen as _);

    if let Some(obj) = parsed_obj_from_state(parser_state) {
        match obj.read(data) {
            Ok(_) => ParserError::ParserOk as u32,
            Err(e) => e as u32,
        }
    } else {
        ParserError::NoMemoryForState as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn _getNumItems(
    _ctx: *const parser_context_t,
    tx_t: *const parse_tx_t,
    num_items: *mut u8,
) -> u32 {
    if tx_t.is_null() || (*tx_t).state.is_null() || num_items.is_null() {
        return ParserError::NoData as u32;
    }
    if let Some(obj) = parsed_obj_from_state(tx_t as _) {
        match obj.num_items() {
            Ok(n) => {
                *num_items = n;
                ParserError::ParserOk as u32
            }
            Err(e) => e as u32,
        }
    } else {
        ParserError::NoData as u32
    }
}

#[no_mangle]
pub unsafe extern "C" fn _getItem(
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
    *pageCount = 0u8;
    let page_count = &mut *pageCount;
    let key = core::slice::from_raw_parts_mut(outKey as *mut u8, outKeyLen as usize);
    let value = core::slice::from_raw_parts_mut(outValue as *mut u8, outValueLen as usize);
    if tx_t.is_null() || (*tx_t).state.is_null() {
        return ParserError::ContextMismatch as _;
    }
    if let Some(obj) = parsed_obj_from_state(tx_t as _) {
        match obj.get_item(displayIdx, key, value, pageIdx) {
            Ok(page) => {
                *page_count = page;
                ParserError::ParserOk as _
            }
            Err(e) => e as _,
        }
    } else {
        ParserError::ContextMismatch as _
    }
}

#[no_mangle]
pub unsafe extern "C" fn _auth_flag(tx_t: *const parse_tx_t, auth_flag: *mut u8) -> u32 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        *auth_flag = tx.auth_flag() as u8;
        ParserError::ParserOk as _
    } else {
        ParserError::ContextMismatch as _
    }
}

#[no_mangle]
pub unsafe extern "C" fn _fee_bytes(tx_t: *const parse_tx_t, fee: *mut u8, fee_len: u16) -> u8 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        let fee_bytes = if let Some(fee) = tx.fee() {
            fee.to_be_bytes()
        } else {
            return 0;
        };

        if fee_bytes.len() <= fee_len as usize {
            fee.copy_from(fee_bytes.as_ptr(), fee_bytes.len());
            return fee_bytes.len() as u8;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _nonce_bytes(
    tx_t: *const parse_tx_t,
    nonce: *mut u8,
    nonce_len: u16,
) -> u8 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        let nonce_bytes = if let Some(nonce) = tx.nonce() {
            nonce.to_be_bytes()
        } else {
            return 0;
        };

        if nonce_bytes.len() <= nonce_len as usize {
            nonce.copy_from(nonce_bytes.as_ptr(), nonce_bytes.len());
            return nonce_bytes.len() as u8;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _check_pubkey_hash(
    tx_t: *const parse_tx_t,
    pubKey: *const u8,
    pubKeyLen: u16,
) -> u32 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        if pubKey.is_null() {
            return ParserError::NoData as _;
        }
        let pk = core::slice::from_raw_parts(pubKey, pubKeyLen as _);
        tx.check_signer_pk_hash(pk) as _
    } else {
        ParserError::ContextMismatch as _
    }
}

#[no_mangle]
pub unsafe extern "C" fn _presig_hash_data(
    tx_t: *const parse_tx_t,
    buf: *mut u8,
    bufLen: u16,
) -> u16 {
    let buffer = core::slice::from_raw_parts_mut(buf, bufLen as usize);

    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        if let Ok(len) = tx.transaction_auth.initial_sighash_auth(buffer) {
            return len as _;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _last_block_ptr(
    tx_t: *const parse_tx_t,
    block_ptr: *mut *const u8,
) -> u16 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        let block = tx.last_transaction_block();
        *block_ptr = block.as_ptr();
        return block.len() as _;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _is_multisig(tx_t: *const parse_tx_t) -> u8 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        tx.is_multisig() as _
    } else {
        false as _
    }
}

#[no_mangle]
pub unsafe extern "C" fn _hash_mode(tx_t: *const parse_tx_t, hash_mode: *mut u8) -> u32 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        match tx.hash_mode() {
            Ok(hm) => {
                *hash_mode = hm as u8;
                ParserError::ParserOk as _
            }
            Err(e) => e as _,
        }
    } else {
        ParserError::ContextMismatch as _
    }
}

#[no_mangle]
pub unsafe extern "C" fn _num_multisig_fields(tx_t: *const parse_tx_t) -> u32 {
    parsed_obj_from_state(tx_t as _)
        .and_then(|obj| obj.transaction())
        .and_then(|tx| tx.transaction_auth.num_auth_fields())
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn _get_multisig_field(
    tx_t: *const parse_tx_t,
    index: u32,
    id: *mut u8,
    data: *mut *const u8,
) -> ParserError {
    let auth_field = parsed_obj_from_state(tx_t as _)
        .and_then(|obj| obj.transaction())
        .and_then(|tx| tx.transaction_auth.get_auth_field(index))
        .unwrap_or(Err(ParserError::ContextMismatch));

    match auth_field {
        Ok(af) => match af {
            TransactionAuthField::PublicKey(i, pubkey) => {
                *id = i as u8;
                *data = pubkey.as_ptr();
                ParserError::ParserOk as _
            }
            TransactionAuthField::Signature(i, sig) => {
                *id = i as u8;
                *data = sig.as_ptr();
                ParserError::ParserOk as _
            }
        },
        Err(e) => {
            *data = core::ptr::null_mut();
            e
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn _transaction_type(tx_t: *const parse_tx_t) -> Tag {
    if let Some(obj) = parsed_obj_from_state(tx_t as _) {
        obj.get_type()
    } else {
        Tag::Invalid
    }
}

#[no_mangle]
pub unsafe extern "C" fn _previous_signer_data(
    tx_t: *const parse_tx_t,
    data: *mut *const u8,
) -> u16 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.transaction()) {
        if let Some(slice) = tx.previous_signer_data() {
            *data = slice.as_ptr();
            return slice.len() as _;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _structured_msg_hash(
    tx_t: *const parse_tx_t,
    out: *mut u8,
    out_len: u16,
) -> u32 {
    if let Some(tx) = parsed_obj_from_state(tx_t as _).and_then(|obj| obj.structured_msg()) {
        let output = core::slice::from_raw_parts_mut(out, out_len as _);
        if tx.get_hash(output).is_ok() {
            return ParserError::ParserOk as _;
        }
    }
    ParserError::UnexpectedError as _
}
