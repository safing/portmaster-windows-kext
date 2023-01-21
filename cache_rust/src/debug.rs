use alloc::string;

extern {
    fn DbgPrint(str: *const u8);
}

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 { 0 }

pub fn _print(str: string::String) {
    unsafe {
        DbgPrint(str.as_ptr());
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => (crate::debug::_print(alloc::format!($($arg)*)));
}
