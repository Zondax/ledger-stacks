use crate::parser::{ParsedObj, ParserError};

#[repr(C)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u32,
    pub offset: u32,
}

#[repr(C)]
pub struct parse_tx_t {
    pub state: *mut u8,
    pub len: u16,
}

/// #Safety
/// Enough space was allocated to store a ParsedObj
pub unsafe fn parsed_obj_from_state<'a>(tx: *mut parse_tx_t) -> Option<&'a mut ParsedObj<'a>> {
    ((*tx).state as *const u8 as *mut ParsedObj).as_mut()
}

#[no_mangle]
pub unsafe extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u32,
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
    bufferSize: u32,
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
