use windows_sys::Win32::Foundation::*;

pub type PVOID = *mut core::ffi::c_void;

extern "system" {
    pub fn MmIsAddressValid(VirtualAddress: PVOID) -> bool;
}




#[cfg(not(test))]
#[no_mangle]
pub extern "system" fn DriverEntry() -> NTSTATUS {
    return STATUS_SUCCESS;
}