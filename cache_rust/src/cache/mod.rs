use alloc::boxed::Box;

pub mod verdict_cache;
pub mod packet_cache;
pub mod packet_key;

use verdict_cache::{VerdictCache, VerdictUpdateInfo};
use packet_cache::PacketCache; 
use crate::{packet_info::PortmasterPacketInfo, common::Verdict, log};


static MAX_VERDICT_CACHE_SIZE: usize = 1024;
static MAX_POCKET_CACHE_SIZE: usize = 1024;

pub static mut VERDICT_CACHE_IPV4: Option<Box<VerdictCache>> = None;
pub static mut VERDICT_CACHE_IPV6: Option<Box<VerdictCache>>  = None; 
pub static mut PACKET_CACHE: Option<Box<PacketCache>> = None; 

#[no_mangle]
pub extern "C" fn initCache() {
    unsafe{
        VERDICT_CACHE_IPV4 = Some(VerdictCache::create(MAX_VERDICT_CACHE_SIZE));
        VERDICT_CACHE_IPV6 = Some(VerdictCache::create(MAX_VERDICT_CACHE_SIZE));
        PACKET_CACHE = Some(PacketCache::create(MAX_POCKET_CACHE_SIZE));
    }
}

#[no_mangle]
pub extern "C" fn clearCache() {
    unsafe {
        VERDICT_CACHE_IPV4 = None;
        VERDICT_CACHE_IPV6 = None;
        PACKET_CACHE = None;
    }
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
    update_info: *mut VerdictUpdateInfo,
) -> i32 {
    unsafe {
        if let Some(info) = update_info.as_mut() {
            if info.is_ipv6() {
                if let Some(cache) = &mut VERDICT_CACHE_IPV6{
                    cache.update(info);
                }
            } else {
                if let Some(cache) = &mut VERDICT_CACHE_IPV4 {
                    cache.update(info);
                }
            }
            return 0;
        } else {
            log!("No verdict cache")
        }
    }
    return 1;
}

/**
 * @brief Adds verdict to cache
 *
 * @par    packetInfo   = pointer to PacketInfo
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
#[no_mangle]
pub extern "C" fn verdictCacheAdd(
    packet_info: *mut PortmasterPacketInfo,
    verdict: Verdict,
    removed_packet_info: *mut *mut PortmasterPacketInfo,
) -> i32 {
    unsafe {
        if let Some(info) = packet_info.as_mut() {
            if info.ip_v6 == 1 {
                if let Some(cache) = &mut VERDICT_CACHE_IPV6{
                    if let Some(removed) = cache.add(info, verdict) {
                        *removed_packet_info = removed;
                    }
                } else {
                    log!("No VERDICT_CACHE_IPV6 cache")
                }
            } else {
                if let Some(cache) = &mut VERDICT_CACHE_IPV4 {
                    if let Some(removed) = cache.add(info, verdict) {
                        *removed_packet_info = removed;
                    }
                } else {
                    log!("No VERDICT_CACHE_IPV4 cache")
                }
            }
            return 0;
        } else {
            log!("No verdict cache 1")
        }
    }
    return 1;
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
    packet_info: *mut PortmasterPacketInfo,
    redir_info: *mut *mut PortmasterPacketInfo,
) -> i32 {
    unsafe {
        if let Some(info) = packet_info.as_mut() {
            if info.ip_v6 == 1 {
                if let Some(cache) = &mut VERDICT_CACHE_IPV6 {
                    if let Ok((info_opt, verdict)) = cache.get(info) {
                        if let Some(rinfo) = info_opt {
                            *redir_info = rinfo;
                        }
                        return verdict as i32;
                    } else {
                        return Verdict::Get as i32;
                    }
                } else {
                    log!("No VERDICT_CACHE_IPV6 cache 1")
                }
            } else {
                if let Some(cache) = &mut VERDICT_CACHE_IPV4 {
                    if let Ok((info_opt, verdict)) = cache.get(info) {
                        if let Some(rinfo) = info_opt {
                            *redir_info = rinfo;
                        }
                        return verdict as i32;
                    } else {
                        return Verdict::Get as i32;
                    }
                } else {
                    log!("No VERDICT_CACHE_IPV4 cache 1")
                }
            };
        }
        return -1;
    }
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
    packet_info: *mut PortmasterPacketInfo,
    packet: *const u8,
    packet_length: usize,
    old_packet_info: *mut *mut PortmasterPacketInfo,
    old_packet: *mut *const u8,
) -> u32 {
    unsafe {
        if let Some(cache) = &mut PACKET_CACHE {
            let (packet_id, removed) = cache.register(packet_info, packet, packet_length);
            if let Some((removed_packet_info, removed_packet)) = removed {
                *old_packet_info = removed_packet_info;
                *old_packet = removed_packet;
            }
            return packet_id; // Ok
        } else {
            log!("No PACKET_CACHE cache 1")
        }
        return 0;
    }
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
    packet_id: u32,
    packet_info_ptr: *mut *mut PortmasterPacketInfo,
    packet: *mut *const u8,
    packet_length: *mut usize,
) -> i32 {
    unsafe {

        if let Some(cache) = &mut PACKET_CACHE {
            let result = cache.retrieve(packet_id);
            if let Some((packet_info_result, packet_result, packet_length_result)) = result {
                *packet_info_ptr = packet_info_result;
                *packet = packet_result;
                *packet_length = packet_length_result;
                log!("Packet retrieved: {}", packet_id);
                return 0; // Ok
            }
        } else {
            log!("No PACKET_CACHE cache 2")
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
    packet_id: u32,
    packet: *mut *const u8,
    packet_length: *mut usize,
) -> i32 {
    unsafe {
        if let Some(cache) = &mut PACKET_CACHE {
            let result = cache.get(packet_id);
            if let Some((_, packet_result, packet_length_result)) = result {
                *packet = packet_result;
                *packet_length = packet_length_result;
                log!("Packet get: {}", packet_id);
                return 0; // Ok
            }
        }else {
            log!("No PACKET_CACHE cache 3")
        }

    }
    return 1; // error
}