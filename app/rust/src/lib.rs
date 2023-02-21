#![no_std]
#![no_builtins]
#![macro_use]
#![allow(dead_code)]
#![deny(unused_crate_dependencies)]

extern crate no_std_compat as std;

mod bolos;
pub mod parser;
mod zxformat;

#[cfg(not(any(test, fuzzing)))]
use core::panic::PanicInfo;

#[cfg(not(any(test, fuzzing)))]
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
    #[cfg(not(any(test, fuzzing)))]
    unsafe {
        check_canary();
    }
}

pub fn pic_internal<T: Sized>(obj: &T) -> &T {
    if cfg!(test) {
        return obj;
    }
    let ptr = obj as *const _;
    let ptr_usize = ptr as *const () as u32;
    unsafe {
        let link = pic(ptr_usize);
        let ptr = link as *const T;
        &*ptr
    }
}

pub fn is_expert_mode() -> bool {
    if cfg!(any(test, fuzzing)) {
        true
    } else {
        unsafe { app_mode_expert() > 0 }
    }
}

#[macro_export]
macro_rules! check_canary {
    () => {
        use crate::canary;
        canary();
    };
}
