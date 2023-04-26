use core::fmt::Debug;
use alloc::format;


#[derive(Copy, Clone, Eq)]
pub struct Key {
    pub local_ip: [u32; 4],
    pub remote_ip: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        if self.local_port != other.local_port {
            return false;
        }

        if self.remote_port != other.remote_port {
            return false;
        }
        
        if self.local_ip != other.local_ip {
            return false;
        }

        if self.remote_ip != other.remote_ip {
            return false;
        }

        return self.protocol == other.protocol
    }
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

impl Ord for Key {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // println!("compare {:?} {:?}", self, other);
        match self.local_port.cmp(&other.local_port) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        
        match self.remote_port.cmp(&other.remote_port) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.local_ip.cmp(&other.local_ip) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.remote_ip.cmp(&other.remote_ip) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        return self.protocol.cmp(&other.protocol)
    }

    fn max(self, other: Self) -> Self
    where
        Self: Sized,
    {
        match self.cmp(&other) {
            core::cmp::Ordering::Less | core::cmp::Ordering::Equal => other,
            core::cmp::Ordering::Greater => self,
        }
    }

    fn min(self, other: Self) -> Self
    where
        Self: Sized,
    {
        match self.cmp(&other) {
            core::cmp::Ordering::Less | core::cmp::Ordering::Equal => self,
            core::cmp::Ordering::Greater => other,
        }
    }

    fn clamp(self, min: Self, max: Self) -> Self
    where
        Self: Sized,
        Self: PartialOrd,
    {
        assert!(min <= max);
        if self < min {
            min
        } else if self > max {
            max
        } else {
            self
        }
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        
        let local_ip: [u8; 16] = unsafe { core::mem::transmute(self.local_ip) };
        let remote_ip: [u8; 16] = unsafe { core::mem::transmute(self.remote_ip) };
        let local = format!("{}.{}.{}.{}:{}", local_ip[0], local_ip[1], local_ip[2], local_ip[3], self.local_port);
        let remote = format!("{}.{}.{}.{}:{}", remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], self.remote_port);
        f.debug_struct("Key")
            .field("local", &local)
            .field("remote", &remote)
            .field("protocol", &self.protocol)
            .finish()
    }
}