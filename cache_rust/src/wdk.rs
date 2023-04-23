use alloc::{string, ffi::CString};
use core::ptr;

use crate::packet_info::PortmasterPacketInfo;

type NdisStatus = i32;

type NetBuffer = *mut u8;
type NetBufferAllocateMDL = *mut u8;


extern {
    // Memory
    fn portmasterMalloc(size: usize, paged: bool) -> *mut u8;
    fn portmasterFree(ptr: *mut u8);

    // Debug
    fn DbgPrint(str: *const i8);

    // Packets
    fn sendBlockPacket(info: *mut PortmasterPacketInfo, data: *const u8, size: usize);
    fn redirectPacket(info: *mut PortmasterPacketInfo, redir_info: *mut PortmasterPacketInfo, data: *const u8, size: usize);
    fn injectPacketCallout(info: *mut PortmasterPacketInfo, data: *const u8, size: usize);

    fn NdisRetreatNetBufferDataStart(net_buffer: NetBuffer, data_offsetDelta: u64, data_back_flip: u64, allocate_mdl_handler: NetBufferAllocateMDL) -> NdisStatus;
    fn NdisGetDataBuffer(net_buffer: NetBuffer, bytes_needed: u64, storage: *mut u8, align_multiple: u64, align_offset: u64) -> *mut u8;


    // TODO: borrowPacketDataFromNB
    // TODO: copyPacketDataFromNB
}



// Needed by the compiler but not used.
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8) -> i32 { 0 }

// Memory
pub fn malloc(size: usize) -> *mut u8{
    unsafe {
        return portmasterMalloc(size, false);
    }
}

pub fn free(ptr: *mut u8) {
    unsafe {
        portmasterFree(ptr);
    }
}

// Debug
pub fn dbg_print(str: string::String) {
    if let Ok(c_str) = CString::new(str) {
        unsafe { 
            DbgPrint(c_str.as_ptr());
        }
    }
}

// Packets
pub fn send_blocked_packet(info: *mut PortmasterPacketInfo, data: *const u8, size: usize) {
    unsafe {
        sendBlockPacket(info, data, size);
    }
}

pub fn redirect_packet(info: *mut PortmasterPacketInfo, redir_info: *mut PortmasterPacketInfo, data: *const u8, size: usize) {
    unsafe {
        redirectPacket(info, redir_info, data, size);
    }
}

pub fn inject_packet_callout(info: *mut PortmasterPacketInfo, data: *const u8, size: usize) {
    unsafe {
        injectPacketCallout(info, data, size);
    }
}

pub fn ndis_retreat_net_buffer_data_start(net_buffer: NetBuffer, data_offset_delta: u64, data_back_flip: u64) -> Result<(), i32>{
    unsafe {
        let result = NdisRetreatNetBufferDataStart(net_buffer, data_offset_delta, data_back_flip, ptr::null_mut());
        if result >= 0 {
            return Ok(());
        }

        return Err(result);
    }
}
