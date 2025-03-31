use core::ffi::CStr;

pub const CONTRACT_ADDR_STR_MAX_LEN: usize = 100;
pub const TOKEN_SYMBOL_MAX_LEN: usize = 20;

#[repr(C)]
pub struct CTokenInfo {
    // Addresses could be shorter than this CONTRACT_ADDR_STR_MAX_LEN
    // containing padded with null bytes
    pub contract_address: [u8; CONTRACT_ADDR_STR_MAX_LEN],
    // symbol could be shorter than this TOKEN_SYMBOL_MAX_LEN
    // containing padded with null bytes
    pub token_symbol: [u8; TOKEN_SYMBOL_MAX_LEN],
    pub decimals: u8,
}

pub struct TokenInfo<'a> {
    pub contract_address: &'a [u8],
    pub token_symbol: &'a [u8],
    pub decimals: u8,
}

extern "C" {
    pub fn get_token(contract_address: *const u8, contract_name: *const u8) -> *const CTokenInfo;
}

// Function to get the length of a null-terminated C string
fn c_strlen(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

/// Retrieves token information by calling the C function `get_token`.
///
/// This function takes a contract address and contract name, converts them to null-terminated
/// byte sequences, and passes them to the C function. It then safely converts the returned
/// C structure into a Rust-friendly `TokenInfo` structure.
///
/// # Parameters
/// * `contract_address` - The contract address as any type that can be converted to a byte slice
/// * `contract_name` - The contract name as any type that can be converted to a byte slice
///
/// # Returns
/// * `Some(TokenInfo)` - If the token was found
/// * `None` - If the token was not found (C function returned null)
///
/// # Safety
/// This function calls an external C function and dereferences the returned pointer.
/// It is safe because:
/// 1. The returned pointer is checked for null
/// 2. The C data is expected to have 'static lifetime (it comes from a global static variable in C)
/// 3. The slices in the returned `TokenInfo` point to this static data
#[cfg(not(any(test, feature = "fuzzing")))]
pub fn get_token_info<T, U>(contract_address: T, contract_name: U) -> Option<TokenInfo<'static>>
where
    T: AsRef<[u8]>,
    U: AsRef<[u8]>,
{
    // To copy the input values to call C interface
    let mut addr_null_term = [0u8; CONTRACT_ADDR_STR_MAX_LEN + 1];
    let mut name_null_term = [0u8; CONTRACT_ADDR_STR_MAX_LEN + 1];

    // Get references to the byte slices
    let addr_bytes = contract_address.as_ref();
    let name_bytes = contract_name.as_ref();

    // Validate inputs
    if addr_bytes.is_empty()
        || name_bytes.is_empty()
        || addr_bytes.len() > CONTRACT_ADDR_STR_MAX_LEN
        || name_bytes.len() > CONTRACT_ADDR_STR_MAX_LEN
    {
        return None;
    }

    // Copy input slices, null termination is already handled by zero-initialization
    addr_null_term[..addr_bytes.len()].copy_from_slice(addr_bytes);
    name_null_term[..name_bytes.len()].copy_from_slice(name_bytes);

    unsafe {
        let c_token_info_ptr = get_token(addr_null_term.as_ptr(), name_null_term.as_ptr());
        if c_token_info_ptr.is_null() {
            return None;
        }

        let c_token_info = &*c_token_info_ptr;
        // Use CStr to safely handle the null-terminated C strings
        let contract_address =
            CStr::from_ptr(c_token_info.contract_address.as_ptr() as *const i8).to_bytes();
        let token_symbol =
            CStr::from_ptr(c_token_info.token_symbol.as_ptr() as *const i8).to_bytes();

        Some(TokenInfo {
            contract_address,
            token_symbol,
            decimals: c_token_info.decimals,
        })
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub fn get_token_info<T, U>(_contract_address: T, _contract_name: U) -> Option<TokenInfo<'static>>
where
    T: AsRef<[u8]>,
    U: AsRef<[u8]>,
{
    None
}
