#![allow(dead_code)]

pub const IPV4_LOCALHOST_NET_MASK: u32 =  0xFF000000;
pub const IPV4_LOCALHOST_NET: u32 = 0x7F000000;

pub const IPV4_LOCALHOST_IP_NETWORK_ORDER: u32 = 0x0100007f;

pub const IPV6_LOCALHOST_PART4              : u32 = 0x1;
pub const IPV6_LOCALHOST_PART4_NETWORK_ORDER: u32 = 0x01000000;

pub const PORT_DNS: u16 = 53;
pub const PORT_DNS_NBO: u16 = 0x3500;

pub const PORT_PM_SPN_ENTRY: u16 = 717;
pub const PORT_PM_SPN_ENTRY_NBO: u16 = 0xCD02;

pub const PORT_PM_API: u16 = 817;

pub const IPV4: u8 = 4;
pub const IPV6: u8 = 6;

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
#[repr(u8)]
pub enum Protocol {
    HOPOPT  = 0,
    ICMP    = 1,
    IGMP    = 2,
    IPV4    = 4,
    TCP     = 6,
    UDP     = 17,
    RDP     = 27,
    DCCP    = 33,
    IPV6    = 41,
    ICMPV6  = 58,
    UDPLITE = 136,
}

pub const ICMPV4_CODE_DESTINATION_UNREACHABLE: u32 = 3;
pub const ICMPV4_CODE_DU_PORT_UNREACHABLE: u32 = 3;              // Destination Unreachable (Port unreachable) ;
pub const ICMPV4_CODE_DU_ADMINISTRATIVELY_PROHIBITED: u32 = 13;  // Destination Unreachable (Communication Administratively Prohibited) ;

pub const ICMPV6_CODE_DESTINATION_UNREACHABLE: u32 = 1;
pub const ICMPV6_CODE_DU_PORT_UNREACHABLE: u32 = 4;              // Destination Unreachable (Port unreachable) ;

pub const DIRECTION_OUTBOUND: u8 = 0;
pub const DIRECTION_INBOUND : u8 = 1;


#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum Verdict {
    Error = 0,
    Get = 1,                // Initial state of packet is undefined -> ask Portmaster what to do
    Accept = 2,             // Accept packets and reinject them
    Block = 3,              // Drop packets silently
    Drop = 4,               // Block packets with RST or FIN
    RedirectDns = 5,        // Redirect packets to DNS
    RedirectTunnel = 6,     // Redirect packets to tunnel.
}

impl Verdict {
    pub fn is_redirect(&self) -> bool {
        match self {
            Verdict::RedirectDns | Verdict::RedirectTunnel => {
                return true;
            }
            _ => {
                return false;
            },
        }
    }
}


const SIOCTL_TYPE: u32 = 40000;
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        ($device_type << 16) | ($access << 14) | ($function << 2) | $method
    };
}

pub const METHOD_BUFFERED: u32 = 0;
pub const METHOD_IN_DIRECT: u32 = 1;
pub const METHOD_OUT_DIRECT: u32 = 2;
pub const METHOD_NEITHER: u32 = 3;

pub const FILE_READ_DATA: u32 = 0x0001;    // file & pipe
pub const FILE_WRITE_DATA: u32 = 0x0002;    // file & pipe

pub const IOCTL_VERSION: u32 = ctl_code!(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);
pub const IOCTL_SHUTDOWN_REQUEST: u32 = ctl_code!(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);
pub const IOCTL_RECV_VERDICT_REQ: u32 = ctl_code!(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);
pub const IOCTL_SET_VERDICT: u32 = ctl_code!(SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);
pub const IOCTL_GET_PAYLOAD: u32 = ctl_code!(SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);
pub const IOCTL_CLEAR_CACHE: u32 = ctl_code!(SIOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);
pub const IOCTL_UPDATE_VERDICT: u32 = ctl_code!(SIOCTL_TYPE, 0x806, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA);

/*
 * IPv4 Header.
 */
#[repr(C)]
#[allow(dead_code)]
struct IPv4Header{
    pub hdr_length_and_version: u8, // to variables 4 bits each 
    pub tos: u8,
    pub length: u16,
    pub id: u16,
    pub frag_off0: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

/*
 * IPv6 Header.
 */
#[repr(C)]
#[allow(dead_code)]
struct IPv6Header {
    pub traffic_class0_and_version: u8, // two variables 4 bits each 
    pub flow_label0_and_traffic_class: u8, // two variables 4 bits each 
    pub flow_label1: u16, 
    pub length: u16, 
    pub next_hdr: u8, 
    pub hop_limit: u8, 
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
}

/*
 * TCP Header.
 */
#[repr(C)]
#[allow(dead_code)]
pub struct TCPHeader {
    pub src_port: u16, 
    pub dst_port: u16, 
    pub seq_num: u32, 
    pub ack_num: u32, 
    pub hdr_length: u8,  // fist 4 bits are reserved, the value is stored in the last 4 bites.
    pub flags: u8,  // [Fin, Syn, Rst, Psh, Ack, Urg, Res, Res]
    pub window: u16, 
    pub checksum: u16, 
}

/*
 * UDP Header.
 */
#[repr(C)]
#[allow(dead_code)]
pub struct UDPHeader {
    pub src_port: u16, 
    pub dst_port: u16, 
    pub length: u16, 
    pub checksum: u16, 
}

/*
* ICMP Header (used also for ICMPv6)
* Note: This header is used only for ICMP type Destination Unreachable (3). It is not valid for the other message types.
*/
#[repr(C)]
#[allow(dead_code)]
struct ICMPHeader {
  pub r#type: u8,  		// message type
  pub code: u8, 		// type sub-code
  pub checksum: u16, 
  pub unused: u32, 
  // This header is not complete for all ICMP packets variants
}

