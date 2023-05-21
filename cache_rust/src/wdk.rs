use alloc::{string, ffi::CString};
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_INTERNAL_ERROR, STATUS_INSUFFICIENT_RESOURCES};
use core::ptr;

use crate::packet_info::PortmasterPacketInfo;

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

    fn NdisRetreatNetBufferDataStart(net_buffer: NetBuffer, data_offsetDelta: u64, data_back_flip: u64, allocate_mdl_handler: NetBufferAllocateMDL) -> NTSTATUS;
    fn NdisGetDataBuffer(net_buffer: NetBuffer, bytes_needed: u64, storage: *mut u8, align_multiple: u64, align_offset: u64) -> *mut u8;

    fn NetBufferDataLength(net_buffer: NetBuffer) -> usize;
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

pub fn ndis_retreat_net_buffer_data_start(net_buffer: NetBuffer, data_offset_delta: u64, data_back_flip: u64) -> Result<(), NTSTATUS>{
    unsafe {
        let result = NdisRetreatNetBufferDataStart(net_buffer, data_offset_delta, data_back_flip, ptr::null_mut());
        if result > 0 {
            return Ok(());
        }

        return Err(result);
    }
}



/*
 * "Borrows" data from net buffer without actually coping it
 * This is faster, but does not always succeed.
 * Called by classifyAll.
 */
#[no_mangle]
pub extern "C" fn borrowPacketDataFromNB(net_buffer: NetBuffer, bytes_needed: usize, data: *mut *mut u8) -> NTSTATUS {
    unsafe {
        if net_buffer.as_ref() == None || data.as_ref() == None {
            return STATUS_INVALID_PARAMETER;
        }

        let result = NdisGetDataBuffer(net_buffer, bytes_needed as u64, ptr::null_mut(), 1, 0);
        if result.as_ref() != None {
            *data = result;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_INTERNAL_ERROR;
}


/*
 * copies packet data from net buffer "nb" to "data" up to the size "maxBytes"
 * actual bytes copied is stored in "dataLength"
 * returns NTSTATUS
 * Called by classifyAll and redir_from_callout if "borrow_packet_data_from_nb" fails
 *
 * NET_BUFFER_LIST can hold multiple NET_BUFFER in rare edge cases. Ignoring these is ok for now.
 * TODO: handle these cases.
 */
#[no_mangle]
pub extern "C" fn copyPacketDataFromNB(net_buffer: NetBuffer, mut max_bytes: usize, data: *mut *mut u8, data_length_ptr: *mut usize) -> NTSTATUS {
    unsafe {
        if net_buffer.as_ref() == None || data.as_ref() == None || data_length_ptr.as_ref() == None {
            return STATUS_INVALID_PARAMETER;
        }

        *data_length_ptr = NetBufferDataLength(net_buffer);
        if let Some(length) = data_length_ptr.as_mut() {
            if max_bytes == 0 || max_bytes > *length {
                max_bytes = *length;
            } else {
                *length = max_bytes;
            }
        };
        

        *data = malloc(max_bytes);
        if *data == ptr::null_mut() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // Copy data from NET_BUFFER
        let mut ptr = NdisGetDataBuffer(net_buffer, max_bytes as u64, ptr::null_mut(), 1, 0);
        if ptr != ptr::null_mut() {
            // Contiguous (common) case:
            // RtlCopyMemory(*data, ptr, max_bytes);
            ptr::copy_nonoverlapping(*data, ptr, max_bytes);
        } else {
            // Non-contigious case:
            ptr = NdisGetDataBuffer(net_buffer, max_bytes as u64, *data, 1, 0);
            if ptr == ptr::null_mut() {
                return STATUS_INTERNAL_ERROR;
            }
        }
    }
    return STATUS_SUCCESS;
}