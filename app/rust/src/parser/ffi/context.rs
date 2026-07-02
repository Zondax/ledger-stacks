use crate::parser::{ParsedObj, ParserError};

#[repr(C)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub buffer_len: u32,
    pub offset: u32,
}

#[repr(C)]
pub struct parse_tx_t {
    pub state: *mut u8,
    pub len: u16,
}

/// # Safety
///
/// `tx` must point to a valid `parse_tx_t` whose `state` field points to a
/// region of at least `size_of::<ParsedObj>()` bytes that the C side allocated
/// (and aligned) using the size reported by [`_parser_init`].
// The C allocator reserves `size_of::<ParsedObj>()` bytes with suitable
// alignment, so reinterpreting the `*mut u8` state pointer as `*mut ParsedObj`
// is sound. (The alignment concern clippy's pedantic `cast_ptr_alignment` would
// raise cannot be seen across the FFI boundary; that lint is not in the default
// set, so no allow is needed here.)
pub unsafe fn parsed_obj_from_state<'a>(tx: *mut parse_tx_t) -> Option<&'a mut ParsedObj<'a>> {
    ((*tx).state as *mut ParsedObj).as_mut()
}

/// # Safety
///
/// `ctx` and `alloc_size` must be valid, non-null pointers, and `buffer` must
/// point to at least `buffer_size` bytes (or be null with `buffer_size == 0`).
#[no_mangle]
pub unsafe extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    buffer_size: u32,
    alloc_size: *mut u16,
) -> u32 {
    // Lets the caller know how much memory we need for allocating
    // our global state
    if alloc_size.is_null() {
        return ParserError::NoMemoryForState as u32;
    }
    *alloc_size = core::mem::size_of::<ParsedObj>() as u16;
    parser_init_context(ctx, buffer, buffer_size) as u32
}

/// # Safety
/// Called after zb_allocate assign memory
/// to store the ParsedObj. This memory outlives
/// the parsed and is deallocated before signing
/// at such point the rust-parser is not used anymore
unsafe fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    buffer_size: u32,
) -> ParserError {
    (*ctx).offset = 0;

    if buffer_size == 0 || buffer.is_null() {
        (*ctx).buffer = core::ptr::null_mut();
        (*ctx).buffer_len = 0;
        return ParserError::InitContextEmpty;
    }

    (*ctx).buffer = buffer;
    (*ctx).buffer_len = buffer_size;
    ParserError::ParserOk
}
