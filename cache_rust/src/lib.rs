#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(lang_items)]
#![feature(const_trait_impl)]
#![feature(core_panic)]
// #![feature(catch_unwind)]
mod allocator;
pub mod lock;
mod packet_cache;
mod verdict_cache;
mod packet_info;
mod packet_key;
mod debug;
extern crate alloc;

use no_panic::no_panic;
use alloc::boxed::Box;
use alloc::vec::Vec;
use packet_info::PortmasterPacketInfo;
use core::panic::PanicInfo;
use packet_cache::*;
use verdict_cache::*;

static mut VERDICT_CACHES: Vec<Box<VerdictCache>> = Vec::new();
static mut PACKET_CACHES: Vec<Box<PacketCache>> = Vec::new();

#[no_panic]
#[no_mangle]
pub extern "C" fn verdictCacheCreate(max_size: u32, verdict_cache: *mut *mut VerdictCache) -> i32 {
    log!("Init Verdict Cache: {}", max_size);
    let mut cache_box = VerdictCache::create(max_size);
    unsafe {
        *verdict_cache = cache_box.as_mut();
        VERDICT_CACHES.push(cache_box);
    }

    return 0;
}

/**
 * @brief Remove all items from verdict cache
 *
 * @par    verdict_cache = VerdictCache to use
 * @par    freeData = callback function that is executed for each item before delete were the data of the item can be deleted
 *
 */
#[no_panic]
#[no_mangle]
pub extern "C" fn verdictCacheClear(
    verdict_cache: *mut VerdictCache,
    free_data: extern "C" fn(*mut PortmasterPacketInfo, u8),
) {
    unsafe {
        (*verdict_cache).clear(free_data);
    }
}

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn verdictCacheTeardown(
    verdict_cache: *mut VerdictCache,
    free_data: extern "C" fn(*mut PortmasterPacketInfo, u8),
) -> i32 {
    unsafe {
        (*verdict_cache).teardown(free_data);
        VERDICT_CACHES.retain(|x| x.as_ref() as *const VerdictCache != verdict_cache);
    }
    return 0;
}

/**
 * @brief Updates a verdict that is already in the cache
 *
 * @par    verdict_cache = VerdictCache to use
 * @par    info   = pointer to verdictUpdateInfo
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn verdictCacheUpdate(
    verdict_cache: *mut VerdictCache,
    update_info: *mut VerdictUpdateInfo,
) -> i32 {
    unsafe {
        if let Some(info) = update_info.as_mut() {
            (*verdict_cache).update(info);
            return 0;
        }
    }
    return 1;
}

/**
 * @brief Adds verdict to cache
 *
 * @par    verdictCache = VerdictCache to use
 * @par    packetInfo   = pointer to PacketInfo
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn verdictCacheAdd(
    verdict_cache: *mut VerdictCache,
    packet_info: *mut PortmasterPacketInfo,
    verdict: Verdict,
    removed_packet_info: *mut *mut PortmasterPacketInfo,
) -> i32 {
    unsafe {
        if let Some(info) = packet_info.as_mut() {
            let removed = (*verdict_cache).add(info, verdict);
            if let Some(removed_info) = removed {
                *removed_packet_info = removed_info;
            }
        } else {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief returns the verdict of a packet if inside the cache, with redirect info if available
 *
 * @par    verdictCache = VerdictCache to use
 * @par    packetInfo   = pointer to PacketInfo
 * @par    redirInfo    = double pointer to packetInfo (return value)
 * @par    verdict       = pointer to verdict (return value)
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn verdictCacheGet(
    verdict_cache: *mut VerdictCache,
    packet_info: *mut PortmasterPacketInfo,
    redir_info: *mut *mut PortmasterPacketInfo,
) -> i32 {
    unsafe {
        if let Some(info) = packet_info.as_mut() {
            if let Ok((info_opt, verdict)) = (*verdict_cache).get(info) {
                if let Some(info) = info_opt {
                    *redir_info = info;
                }
                return verdict as i32;
            } else {
                return 1;
            }
        } else {
            return -1;
        }
    }
}

/**
 * @brief Initializes the packet cache
 *
 * @par    maxSize     = size of cache
 * @par    packetCache = returns new packet_cache_t
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn packetCacheCreate(max_size: usize, packet_cache: *mut *mut PacketCache) -> i32 {
    log!("Init Packet Cache: {}", max_size);
    let mut cache_box = PacketCache::create(max_size);
    unsafe {
        *packet_cache = cache_box.as_mut();
        //PACKET_CACHES.push(cache_box);
    }
    return 0;
}

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn packetCacheTeardown(
    packet_cache: *mut PacketCache,
    free_data: extern "C" fn(*mut PortmasterPacketInfo, *const u8),
) -> i32 {
    unsafe {
        (*packet_cache).teardown(free_data);
        PACKET_CACHES.retain(|x| x.as_ref() as *const PacketCache != packet_cache);
    }
    return 0;
}

/**
 * @brief Registers a packet
 *
 * @par    packetCache = packetCache to use
 * @par    packetInfo  = pointer to packetInfo
 * @par    packet      = pointer to packet
 * @return new packet ID
 *
 */
#[no_mangle]
pub extern "C" fn packetCacheRegister(
    packet_cache: *mut PacketCache,
    packet_info: *mut PortmasterPacketInfo,
    packet: *const u8,
    packet_length: usize,
    old_packet_info: *mut *mut PortmasterPacketInfo,
    old_packet: *mut *const u8,
) -> u32 {
    unsafe {
        if let Some(packet_cache) = packet_cache.as_mut() {
            let (packet_id, removed) = packet_cache.register(packet_info, packet, packet_length);
            if let Some((removed_packet_info, removed_packet)) = removed {
                *old_packet_info = removed_packet_info;
                *old_packet = removed_packet;
            }
            return packet_id; // Ok
        }
    }
    return 0; // error
}

/**
 * @brief Retrieves and deletes a packet from list, if it exists.
 *
 * @par    packetCache  = packetCache to use
 * @par    packetID     = registered packet ID
 * @par    packetCache  = double pointer for packetInfo return
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn packetCacheRetrieve(
    packet_cache: *mut PacketCache,
    packet_id: u32,
    packet_info_ptr: *mut *mut PortmasterPacketInfo,
    packet: *mut *const u8,
    packet_length: *mut usize,
) -> i32 {
    unsafe {
        if let Some(packet_cache) = packet_cache.as_mut() {
            let result = packet_cache.retrieve(packet_id);
            if let Some((packet_info_result, packet_result, packet_length_result)) = result {
                *packet_info_ptr = packet_info_result;
                *packet = packet_result;
                *packet_length = packet_length_result;
                log!("Packet retrieved: {}", packet_id);
                return 0; // Ok
            } 
        }
    }
    return 1; // error
}

/**
 * @brief Retrieves a packet from list, if it exists.
 *
 * @par    packetCache = packetCache to use
 * @par    packetID    = registered packet ID
 * @par    packet      = double pointer for packet return
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn packetCacheGet(
    packet_cache: *mut PacketCache,
    packet_id: u32,
    packet: *mut *const u8,
    packet_length: *mut usize,
) -> i32 {
    unsafe {
        if let Some(packet_cache) = packet_cache.as_mut() {
            let result = packet_cache.get(packet_id);
            if let Some((_, packet_result, packet_length_result)) = result {
                *packet = packet_result;
                *packet_length = packet_length_result;
                log!("Packet get: {}", packet_id);
                return 0; // Ok
            } 
        }
    }
    return 1; // error
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // let mut host_stderr = HStderr::new();

    // // logs "panicked at '$reason', src/main.rs:27:4" to the host stderr
    // writeln!(host_stderr, "{}", info).ok();
    log!("{}", info);
    // unsafe {
    //     driverPanic();
    // }
    loop {}
}

#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
