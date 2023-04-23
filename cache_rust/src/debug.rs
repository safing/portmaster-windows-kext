#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => (crate::wdk::dbg_print(alloc::format!($($arg)*)));
}
