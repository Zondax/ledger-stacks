// no_std only on the bare-metal device target; host builds (tests, clippy,
// fuzzing) link std, which also provides the panic handler defined below.
#![cfg_attr(target_os = "none", no_std)]
#![no_builtins]
#![macro_use]

extern crate no_std_compat as std;

mod bolos;
pub mod parser;
mod zxformat;

// The panic handler is only needed on the bare-metal device target; on host
// builds (tests, clippy, fuzzing) std already provides one, so defining ours
// would clash (duplicate `panic_impl` lang item).
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// These SDK symbols are only referenced by the device build; on host/test builds
// their callers are compiled out, so the declarations would otherwise be dead.
#[cfg(not(any(test, feature = "fuzzing")))]
extern "C" {
    fn check_canary();
    fn app_mode_expert() -> u8;
}

pub(crate) fn canary() {
    #[cfg(not(any(test, feature = "fuzzing")))]
    unsafe {
        check_canary();
    }
}

#[cfg(not(any(test, feature = "fuzzing")))]
pub fn is_expert_mode() -> bool {
    unsafe { app_mode_expert() > 0 }
}

#[cfg(any(test, feature = "fuzzing"))]
pub fn is_expert_mode() -> bool {
    true
}

#[macro_export]
macro_rules! check_canary {
    () => {
        use $crate::canary;
        canary();
    };
}

