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

/// A handler struct to deal with
/// static global variables and PIC
pub struct GlobalVariable<T: Sized + 'static>(T);

impl<T> GlobalVariable<T>
where
    T: Sized + 'static,
{
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<T> core::ops::Deref for GlobalVariable<T>
where
    T: Sized + 'static,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
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

extern "C" {
    fn pic(link_address: u32) -> u32;
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

#[macro_export]
macro_rules! pic {
    ($obj:expr) => {{
        use crate::pic_internal;
        pic_internal(&$obj)
    }};
}

#[macro_export]
macro_rules! check_canary {
    () => {
        use crate::canary;
        canary();
    };
}
