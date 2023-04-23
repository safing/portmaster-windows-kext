use alloc::{boxed::Box, vec::Vec};

use crate::{packet_info::PortmasterPacketInfo, lock::KSpinLock, log};

struct Item {
    packet_id: u32,
    packet_info: *mut PortmasterPacketInfo,
    packet: *const u8,
    packet_length: usize,
}

pub struct PacketCache {
    items: Vec<Option<Item>>,
    next_packet_id: usize,

    spin_lock: KSpinLock,
}

unsafe impl Sync for PacketCache {}

impl PacketCache {
    pub fn create(max_size: usize) -> Box<PacketCache> {
        log!("packet cache create");

        let mut items = Vec::with_capacity(max_size);
        for _ in 0..max_size {
            items.push(None);
        }

        let cache = Box::new(PacketCache {
            items: items,
            next_packet_id: 1,
            spin_lock: KSpinLock::create()
        });

        return cache;
    }

    pub fn teardown(&mut self, free_data: extern "C" fn(*mut PortmasterPacketInfo, *const u8)) {
        self.clear(free_data);
        self.next_packet_id = 1;
    }

    pub fn clear(&mut self, free_data: extern "C" fn(*mut PortmasterPacketInfo, *const u8)) {
        let _lock_guard = self.spin_lock.lock();
        for i in &self.items {
            if let Some(item) = i {
                free_data(item.packet_info, item.packet);
            }
        }
        self.items.clear()
    }

    fn get_index_from_packet_id(&self, packet_id: u32) -> u32 {
        return packet_id % self.items.capacity() as u32;
    }

    pub fn register(
        &mut self,
        packet_info: *mut PortmasterPacketInfo,
        packet: *const u8,
        packet_length: usize,
    ) -> (u32, Option<(*mut PortmasterPacketInfo, *const u8)>) {
        log!("packet cache register");

        let _lock_guard = self.spin_lock.lock();
        
        let packet_id = self.next_packet_id as u32;
        let index_to_write = self.get_index_from_packet_id(packet_id) as usize;

        self.next_packet_id += 1;

        let mut removed = None;
        if let Some(i) = &mut self.items[index_to_write] {
            removed = Some((i.packet_info, i.packet));
        }

        self.items[index_to_write] = Some(Item {
            packet_id: packet_id,
            packet_info: packet_info,
            packet: packet,
            packet_length: packet_length,
        });

        return (packet_id, removed);
    }
    fn is_packet_id_valid(&self, packet_id: u32) -> bool {
        if packet_id == 0 {
            return false;
        }

        if packet_id as i64 <= (self.next_packet_id as i64 - (self.items.capacity() - 1) as i64) {
            return false;
        }

        return true;
    }

    pub fn retrieve(&mut self, packet_id: u32) -> Option<(*mut PortmasterPacketInfo, *const u8, usize)> {
        log!("packet cache retrieve");
        let _lock_guard = self.spin_lock.lock();

        if !self.is_packet_id_valid(packet_id) {
            return None;
        }

        let index = self.get_index_from_packet_id(packet_id) as usize;

        let mut result = None;
        if let Some(item) = &mut self.items[index] {
            if item.packet_id == packet_id {
                result = Some((item.packet_info, item.packet, item.packet_length));
            }
        }

        if result != None {
            self.items[index] = None;
        }

        return result;
    }

    pub fn get(&mut self, packet_id: u32) -> Option<(*mut PortmasterPacketInfo, *const u8, usize)> {
        log!("packet cache get");
        let _lock_guard = self.spin_lock.lock();

        if !self.is_packet_id_valid(packet_id) {
            return None;
        }

        let index = self.get_index_from_packet_id(packet_id) as usize;

        let mut result = None;
        if let Some(item) = &mut self.items[index] {
            if item.packet_id == packet_id {
                result = Some((item.packet_info, item.packet, item.packet_length));
            }
        }

        return result;
    }
}

