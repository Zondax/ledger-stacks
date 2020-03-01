#![no_std]
#![no_builtins]

#![allow(dead_code, unused_imports)]

mod bolos;

extern crate core;

fn debug(_msg: &str) {}

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_helloworld() {
    }
}
