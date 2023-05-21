use crate::{cache::initCache, fund::DEVICE_OBJECT, log};
use alloc::vec::Vec;
use windows_sys::{
    Wdk::System::SystemServices::RtlInitUnicodeString,
    Win32::Foundation::{LUID, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING},
};

pub type PVOID = *mut core::ffi::c_void;
pub struct HANDLE {
    unused: i32,
}
extern "C" {
    fn initializeInjectHandles() -> NTSTATUS;
    fn initNetBufferPool() -> NTSTATUS;

    // fn RtlInitUnicodeString(str: *mut UNICODE_STRING, source: *mut u16)
}

// #[cfg(not(test))]
#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut DEVICE_OBJECT,
    registry_path: PVOID,
) -> NTSTATUS {
    initCache();
    unsafe {
        let mut result = initializeInjectHandles();
        if result < 0 {
            log!("Failed to initialize inject handlers");
            return result;
        }

        result = initNetBufferPool();
        if result < 0 {
            log!("Failed to initialize net buffer pool");
            return result;
        }
    }

    let mut driver_handle: HANDLE;
    let mut device_handle: HANDLE;

    init_driver_object(
        driver_object,
        registry_path,
        &mut driver_handle,
        &mut device_handle,
    );

    return STATUS_SUCCESS;
}

fn init_driver_object(
    driver_object: *mut DEVICE_OBJECT,
    registry_path: PVOID,
    driver: *mut HANDLE,
    device: *mut HANDLE,
) {
    let mut device_name: UNICODE_STRING;
    let mut device_symlink: UNICODE_STRING;
    unsafe {
        let const_device_name: Vec<u16> = "TODO: set real device name".encode_utf16().collect();
        RtlInitUnicodeString(&mut device_name, const_device_name.as_ptr());

        let const_device_symlink: Vec<u16> =
            "TODO: set real device symlink".encode_utf16().collect();
        RtlInitUnicodeString(&mut device_symlink, const_device_symlink.as_ptr());
    }
}
