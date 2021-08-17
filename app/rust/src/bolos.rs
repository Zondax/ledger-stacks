//! Rust interfaces to Ledger SDK APIs.

extern "C" {
    fn _zemu_log_stack(buffer: *const u8);
}

#[cfg(not(test))]
pub fn c_zemu_log_stack<S: AsRef<[u8]>>(s: S) {
    unsafe { _zemu_log_stack(s.as_ref().as_ptr()) }
}
#[cfg(test)]
pub fn c_zemu_log_stack<S: AsRef<[u8]>>(_s: S) {}
