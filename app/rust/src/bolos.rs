//! Rust interfaces to Ledger SDK APIs.
pub const SHA256_LEN: usize = 32;

extern "C" {
    fn _zemu_log_stack(buffer: *const u8);
}

#[cfg(not(any(test, fuzzing)))]
pub fn c_zemu_log_stack<S: AsRef<[u8]>>(s: S) {
    unsafe { _zemu_log_stack(s.as_ref().as_ptr()) }
}

#[cfg(any(test, fuzzing))]
pub fn c_zemu_log_stack<S: AsRef<[u8]>>(_s: S) {
    std::println!("{:?}", std::str::from_utf8(_s.as_ref()).unwrap());
}

// extern function that uses the device sdk to compute a hash
extern "C" {
    pub fn hash_sha256(in_data: *const u8, in_len: u16, out: *mut u8);
}

#[derive(Debug)]
pub struct OutputTooSmall;

#[cfg(not(any(test, fuzzing)))]
pub fn sha256(data: &[u8], output: &mut [u8]) -> Result<(), OutputTooSmall> {
    if output.len() < SHA256_LEN {
        return Err(OutputTooSmall);
    }

    unsafe {
        hash_sha256(data.as_ptr(), data.len() as _, output.as_mut_ptr());
    }

    Ok(())
}

#[cfg(any(test, fuzzing))]
pub fn sha256(data: &[u8], out: &mut [u8]) -> Result<(), OutputTooSmall> {
    use sha2::Digest;
    use sha2::Sha256;
    let digest = Sha256::digest(data);
    if out.len() != digest.len() {
        return Err(OutputTooSmall);
    }
    out.copy_from_slice(digest.as_slice());
    Ok(())
}
