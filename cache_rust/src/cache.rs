extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::boxed::Box;

use crate::lock::KSpinLock;

const DIRECTION_INBOUND: u8 = 1;
const PORT_PM_SPN_ENTRY: u16 = 717;
const PORT_DNS: u16 = 53;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Verdict {
    Error = 0,
    Get,
    Accept,
    Block,
    Drop,
    RedirDns,
    RedirTunnel,
}

impl Verdict {
    fn is_redirect(&self) -> bool {
        match self {
            Verdict::RedirDns | Verdict::RedirTunnel => {
                return true;
            }
            _ => {
                return false;
            },
        }
    }
}

#[allow(dead_code)]
pub struct PortmasterPacketInfo {
    id: u32,
    process_id: u64,
    direction: u8,
    ip_v6: u8,
    protocol: u8,
    flags: u8,
    local_ip: [u32; 4],
    remote_ip: [u32; 4],
    local_port: u16,
    remote_port: u16,
    compartment_id: u64,
    interface_index: u32,
    sub_interface_index: u32,
    packet_size: u32,
}

impl PortmasterPacketInfo {
    fn get_verdict_key(&self) -> Key {
        Key { local_ip: self.local_ip, 
              local_port: self.local_port,
              remote_ip: self.remote_ip,
              remote_port: self.remote_port, 
              protocol: self.protocol }
    }

    fn get_redirect_key(&self) -> Key {
        Key { local_ip: self.local_ip, 
            local_port: self.local_port,
            remote_ip: self.local_ip,
            remote_port: 0, 
            protocol: self.protocol }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Ord)]
struct Key {
    local_ip: [u32; 4],
    remote_ip: [u32; 4],
    local_port: u16,
    remote_port: u16,
    protocol: u8,
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        match self.local_port.partial_cmp(&other.local_port) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.remote_port.partial_cmp(&other.remote_port) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.local_ip.partial_cmp(&other.local_ip) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        match self.remote_ip.partial_cmp(&other.remote_ip) {
            Some(core::cmp::Ordering::Equal) => {}
            ord => return ord,
        }

        return self.protocol.partial_cmp(&other.protocol)
    }
}

struct VerdictCacheItem {
    packet_info: *mut PortmasterPacketInfo,
    verdict: Verdict,
    last_accessed: u64,
}

pub struct VerdictCache {
    verdicts: BTreeMap<Key, VerdictCacheItem>,
    redirects: BTreeMap<Key, VerdictCacheItem>,

    max_size: usize,
    cache_access_counter: u64,

    spin_lock: KSpinLock,
}

unsafe impl Sync for VerdictCache {}

impl VerdictCache {
    pub fn create(max_size: u32) -> Box<VerdictCache> {
        return Box::new(VerdictCache { 
            verdicts: BTreeMap::new(), 
            redirects: BTreeMap::new(),
            max_size: max_size as usize,
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

    fn update_internal(&mut self, info: &mut PortmasterPacketInfo, verdict: Verdict) {
        if let Some(item) = self.verdicts.get_mut(&info.get_verdict_key()) {
            let old_verdict = item.verdict;
            item.verdict = verdict;

            let redirect_key = info.get_redirect_key();
            if old_verdict.is_redirect() {
                self.redirects.remove(&redirect_key);
            }

            if item.verdict.is_redirect() {
                self.redirects.insert(redirect_key, VerdictCacheItem { 
                    packet_info: item.packet_info,
                    verdict: item.verdict,
                    last_accessed: self.cache_access_counter });
            }
        }
    } 

    pub fn update(&mut self, info: &mut PortmasterPacketInfo, verdict: Verdict) {
        let _lock_guard = self.spin_lock.lock();
        self.update_internal(info, verdict);
    }

    fn remove_last_used(&mut self) -> Result<*mut PortmasterPacketInfo, ()> {
        let mut smallest_access_time = self.cache_access_counter;
        let mut key_to_remove = None;
        
        for (key, item) in &self.verdicts {
            if item.last_accessed < smallest_access_time {
                key_to_remove = Some(*key);
                smallest_access_time = item.last_accessed;
            }
        }
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
        let _lock_guard = self.spin_lock.lock();
        let key = info.get_verdict_key();
        if self.verdicts.contains_key(&key) {
            self.update_internal(info, verdict);
            return None;
        }
        self.cache_access_counter += 1;
        let mut removed_info_opt = None;
        if self.verdicts.len() > self.max_size {
            if let Ok(removed_info) = self.remove_last_used() {
                removed_info_opt = Some(removed_info);
            }
        }

        self.verdicts.insert(key, 
             VerdictCacheItem { 
                packet_info: info, 
                verdict: verdict,
                last_accessed: self.cache_access_counter });

        if verdict.is_redirect() {
            let redirect_key = info.get_redirect_key();
            if !self.redirects.contains_key(&redirect_key) {
                self.redirects.insert(redirect_key,VerdictCacheItem { 
                    packet_info: info, 
                    verdict: verdict,
                    last_accessed: self.cache_access_counter });
            }
        }

        
        return removed_info_opt;
    }

    pub fn get(&mut self, info: &PortmasterPacketInfo) -> Result<(Option<*mut PortmasterPacketInfo>, Verdict), ()> {
        let _lock_guard = self.spin_lock.lock();
        if info.direction == DIRECTION_INBOUND && (info.remote_port == PORT_PM_SPN_ENTRY || info.remote_port == PORT_DNS) {
            if let Some(item) = self.redirects.get_mut(&info.get_redirect_key()) {
                self.cache_access_counter += 1;
                if item.verdict.is_redirect() {
                    item.last_accessed = self.cache_access_counter;
                    return Result::Ok((Option::Some(item.packet_info), item.verdict));
                }
            }
        }

        let result = self.verdicts.get_mut(&info.get_verdict_key());
        if let Some(item) = result {
            let mut redirect = Option::None;
            self.cache_access_counter += 1;
            item.last_accessed = self.cache_access_counter;
            if item.verdict.is_redirect() {
                redirect = Option::Some(item.packet_info);
            }
            return Result::Ok((redirect, item.verdict));
        }

        return Result::Err(())
    }


}

pub struct VerdictUpdateInfo {}

