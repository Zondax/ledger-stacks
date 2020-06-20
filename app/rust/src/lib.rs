#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]
#![macro_use]

#[cfg(test)]
#[macro_use]
extern crate std;

mod bolos;
mod parser;
mod zxformat;

extern crate core;

fn debug(_msg: &str) {}

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

extern "C" {
    fn check_canary();
}

pub(crate) fn canary() {
    #[cfg(not(test))]
    unsafe {
        check_canary();
    }
}

#[macro_export]
macro_rules! check_canary {
    () => {
        use crate::canary;
        canary();
    };
}
