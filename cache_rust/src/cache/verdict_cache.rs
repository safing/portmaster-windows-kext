extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::boxed::Box;
use alloc::rc::Rc;
use crate::common::Verdict;
use crate::lock::KSpinLock;
use crate::log;
use crate::packet_info::PortmasterPacketInfo;

use super::packet_key::Key;

const DIRECTION_INBOUND: u8 = 1;
const PORT_PM_SPN_ENTRY: u16 = 717;
const PORT_DNS: u16 = 53;

#[repr(C)]
pub struct VerdictUpdateInfo {
    local_ip:    [u32; 4], // Source Address, only srcIP[0] if IPv4
	remote_ip:   [u32; 4], // Destination Address
	local_port:  u16,    // Source Port
	remote_port: u16,    // Destination port
	ip_v6:       u8,     // True: IPv6, False: IPv4
	protocol:    u8,     // Protocol (UDP, TCP, ...)
	verdict:     Verdict,     // New verdict
}

impl VerdictUpdateInfo {
    fn get_verdict_key(&self) -> Key {
        Key { local_ip: self.local_ip, 
              local_port: self.local_port,
              remote_ip: self.remote_ip,
              remote_port: self.remote_port, 
              protocol: self.protocol }
    }

    pub fn is_ipv6(&self) -> bool {
        return self.ip_v6 == 1;
    }
}

struct VerdictCacheItem {
    packet_info: *mut PortmasterPacketInfo,
    verdict: Verdict,
    last_accessed: u64,
}

pub struct VerdictCache {
    verdicts: BTreeMap<Key, Rc<VerdictCacheItem>>,
    redirects: BTreeMap<Key, Rc<VerdictCacheItem>>,

    max_size: usize,
    cache_access_counter: u64,

    spin_lock: KSpinLock,
}

unsafe impl Sync for VerdictCache {}

impl VerdictCache {
    pub fn create(max_size: usize) -> Box<VerdictCache> {
        log!("verdict cache create");

        return Box::new(VerdictCache { 
            verdicts: BTreeMap::new(), 
            redirects: BTreeMap::new(),
            max_size: max_size,
            cache_access_counter: 0,
            spin_lock: KSpinLock::create()});
    }

    pub fn clear(&mut self, free_data: extern fn(*mut PortmasterPacketInfo, u8)) {
        let _lock_guard = self.spin_lock.lock();
        for (_, item) in &self.verdicts {
            free_data(item.packet_info, item.verdict as u8);
        }
        self.verdicts.clear();
        self.redirects.clear();
    }

    pub fn teardown(&mut self, free_data: extern fn(*mut PortmasterPacketInfo, u8)) {
        self.clear(free_data);
    }

    fn update_internal(&mut self, mut item: Rc<VerdictCacheItem>, verdict: Verdict) {
        let old_verdict = item.verdict;
        // Update the verdict
        if let Some(i) = Rc::get_mut(&mut item) {
            i.verdict = verdict;
        }

        // Get packet info
        let info: &PortmasterPacketInfo;
        unsafe {
            if let Some(i) = item.packet_info.as_ref() {
                info = i;
            } else {
                // return if packet info was null
                return;
            }
        }
        
        // Remove old redirect if present.
        let redirect_key = info.get_redirect_key();
        if old_verdict.is_redirect() {
            self.redirects.remove(&redirect_key);
        }
        // Add item to redirect map if needed.
        if item.verdict.is_redirect() {
            self.redirects.insert(redirect_key, item.clone());
        }
        
        // Add item to verdicts map.
        self.verdicts.insert(info.get_verdict_key(), item);    
    } 

    pub fn update(&mut self, info: &mut VerdictUpdateInfo) {
        log!("verdict cache update");

        // Lock and call internal update
        let _lock_guard = self.spin_lock.lock();
        if let Some(item) = self.verdicts.remove(&info.get_verdict_key()) {
            self.update_internal(item, info.verdict);
        }
    }

    fn remove_least_used(&mut self) -> Result<*mut PortmasterPacketInfo, ()> {
        let mut smallest_access_time = self.cache_access_counter;
        let mut key_to_remove = None;
        
        // Iterate over all elements and find the smallest access time item.
        for (key, item) in &self.verdicts {
            if item.last_accessed < smallest_access_time {
                key_to_remove = Some(*key);
                smallest_access_time = item.last_accessed;
            }
        }
        // Remove the found element from the verdicts and redirect the maps.
        if let Some(key) = key_to_remove {
            let item = self.verdicts.remove(&key).unwrap();
            if item.verdict.is_redirect() {
                unsafe {
                    _ = self.redirects.remove(&(*item.packet_info).get_redirect_key());
                }
            }
            return Ok(item.packet_info)
        } else {
            return Err(())
        }
    }

    pub fn add(&mut self, info: &mut PortmasterPacketInfo, verdict: Verdict) -> Option<*mut PortmasterPacketInfo> {
        log!("verdict cache add");

        // Lock
        let _lock_guard = self.spin_lock.lock();

        // Check if there is already item with the same key.
        let key = info.get_verdict_key();

        if let Some(item) = self.verdicts.remove(&key) {
            // Update and return.
            self.update_internal(item, verdict);
            return None;
        }
        self.cache_access_counter += 1;

        // Check if we have room for new element.
        let mut removed_info_opt = None;
        if self.verdicts.len() > self.max_size {
            // Remove least recently used.
            if let Ok(removed_info) = self.remove_least_used() {
                removed_info_opt = Some(removed_info);
            }
        }

        // Create new item and add to the map.
        let item = Rc::new(VerdictCacheItem { 
            packet_info: info, 
            verdict: verdict,
            last_accessed: self.cache_access_counter });
        self.verdicts.insert(key, item.clone());

        // Add redirect entry if needed
        if verdict.is_redirect() {
            let redirect_key = info.get_redirect_key();
            if !self.redirects.contains_key(&redirect_key) {
                self.redirects.insert(redirect_key,item);
            }
        }

        // return removed packet info if any
        return removed_info_opt;
    }

    pub fn get(&mut self, info: &PortmasterPacketInfo) -> Result<(Option<*mut PortmasterPacketInfo>, Verdict), ()> {
        log!("verdict cache get");

        // Lock
        let _lock_guard = self.spin_lock.lock();
        self.cache_access_counter += 1;
        
        // Check for redirect.
        if info.direction == DIRECTION_INBOUND && (info.remote_port == PORT_PM_SPN_ENTRY || info.remote_port == PORT_DNS) {
            if let Some(item) = self.redirects.get_mut(&info.get_redirect_key()) {
                if item.verdict.is_redirect() {
                    // Update access time
                    if let Some(item) = Rc::get_mut(item) {
                        item.last_accessed = self.cache_access_counter;
                    }

                    // Return verdict and redirect info
                    return Result::Ok((Option::Some(item.packet_info), item.verdict));
                }
            }
        }

        // Check for verdict.
        let result = self.verdicts.get_mut(&info.get_verdict_key());
        if let Some(item) = result {
            let mut redirect = Option::None;
            // Update access time
            if let Some(item) = Rc::get_mut(item) {
                item.last_accessed = self.cache_access_counter;
            }
    
            // Set redirect info if available.
            if item.verdict.is_redirect() {
                redirect = Option::Some(item.packet_info);
            }
            // Return verdict and redirect info
            return Result::Ok((redirect, item.verdict));
        }

        return Result::Err(())
    }

}
