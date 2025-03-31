#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

mod bolos;
pub mod parser;
mod zxformat;

fn debug(_msg: &str) {}

// Only define panic handler when not fuzzing and not testing
#[cfg(all(not(test), not(feature = "fuzzing"), not(feature = "clippy")))]
use core::panic::PanicInfo;

#[cfg(all(not(test), not(feature = "fuzzing"), not(feature = "clippy")))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

extern "C" {
    fn check_canary();
    fn pic(link_address: u32) -> u32;
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

