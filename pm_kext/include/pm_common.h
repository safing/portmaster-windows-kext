/*
 *  Name:        pm_common.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Common definitions for kernel and userland driver
 *
 *  Scope:       Kernelmode
 *               Userland
 */

#ifndef PM_COMMON_H
#define PM_COMMON_H

#define PORTMASTER_DEVICE_NAME_C "PortmasterKext"
#define PORTMASTER_DEVICE_NAME  L"PortmasterKext"   //Wide String

/****************************************************************************/
/* Portmaster TYPES                                                         */
/****************************************************************************/

/*
 * Container for IPv4 and IPv6 packet information.
 */
//#pragma pack 4
typedef struct {
    UINT32 id;                          //ID from RegisterPacket
    UINT64 processID;                   //Process ID. Nice to have
    UINT8 direction;
    UINT8 ipV6;                         //True: IPv6, False: IPv4
    UINT8 protocol;                     //Protocol (UDP, TCP, ...)
    UINT8 flags;                        //Flags
    UINT32 localIP[4];                  //Source Address, only srcIP[0] if IPv4
    UINT32 remoteIP[4];                 //Destination Address
    UINT16 localPort;                   //Source Port
    UINT16 remotePort;                  //Destination port
    ULONG compartmentId;                //Currently unused
    UINT32 interfaceIndex;              //eth0, ...
    UINT32 subInterfaceIndex;
    UINT32 packetSize;
} PortmasterPacketInfo;

typedef struct {
    UINT32 localIP[4];                  //Source Address, only srcIP[0] if IPv4
    UINT32 remoteIP[4];                 //Destination Address
    UINT16 localPort;                   //Source Port
    UINT16 remotePort;                  //Destination port
    UINT64 receivedBytes;               //Number of bytes recived on this connection
    UINT64 transmittedBytes;            //Number of bytes transsmited from this connection
    UINT8 ipV6;                         //True: IPv6, False: IPv4
    UINT8 protocol;                     //Protocol (UDP, TCP, ...)
} PortmasterConnection;
/*
 * Packet Info Flags
 */
#define PM_STATUS_FAST_TRACK_PERMITTED 0x01
#define PM_STATUS_SOCKET_AUTH          0x02

/*
 * IPv4 Header.
 */
typedef struct {
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} IPv4Header;

/*
 * IPv6 Header.
 */
typedef struct {
    UINT8  TrafficClass0:4;
    UINT8  Version:4;
    UINT8  FlowLabel0:4;
    UINT8  TrafficClass1:4;
    UINT16 FlowLabel1;
    UINT16 Length;
    UINT8  NextHdr;
    UINT8  HopLimit;
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
} IPv6Header;

/*
 * TCP Header.
 */
typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1:4;
    UINT16 HdrLength:4;
    UINT16 Fin:1;
    UINT16 Syn:1;
    UINT16 Rst:1;
    UINT16 Psh:1;
    UINT16 Ack:1;
    UINT16 Urg:1;
    UINT16 Reserved2:2;
    UINT16 Window;
    UINT16 Checksum;
} TCPHeader;

/*
 * UDP Header.
 */
typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
} UDPHeader;

/*
* ICMP Header (used also for ICMPv6)
* Note: This header is used only for ICMP type Destination Unreachable (3). It is not valid for the other message types.
*/
typedef struct
{
  UINT8  Type;		// message type
  UINT8  Code;		// type sub-code
  UINT16 Checksum;
  UINT32 unused;
  // This header is not complete for all ICMP packets variants
}ICMPHeader;

/*
 * Verdict can be permanent or temporary for one specific packet.
 * If verdict is temporary, portmaster returns negativ value of PORTMASTER_VERDICT_*
 */
typedef INT8 verdict_t;
#define PORTMASTER_VERDICT_ERROR 0
#define PORTMASTER_VERDICT_GET 1                // Initial state of packet is undefined -> ask Portmaster what to do
#define PORTMASTER_VERDICT_ACCEPT 2             // Accept packets and reinject them
#define PORTMASTER_VERDICT_BLOCK 3              // Drop packets silently
#define PORTMASTER_VERDICT_DROP 4               // Block packets with RST or FIN
#define PORTMASTER_VERDICT_REDIR_DNS 5          // Redirect packets to DNS
#define PORTMASTER_VERDICT_REDIR_TUNNEL 6       // Redirect packets to tunnel.
static const char* VERDICT_NAMES[] = { "PORTMASTER_VERDICT_ERROR",
                                 "PORTMASTER_VERDICT_GET",
                                 "PORTMASTER_VERDICT_ACCEPT",
                                 "PORTMASTER_VERDICT_BLOCK",
                                 "PORTMASTER_VERDICT_DROP",
                                 "PORTMASTER_VERDICT_REDIR_DNS",
                                 "PORTMASTER_VERDICT_REDIR_TUNNEL" };

/*
 * CACHE SIZES for packet and verdict cache
 * Packet cache:
 * - One entry can be as big as the MTU - eg. 1500 Bytes.
 * - A size of 1024 with a mean entry size of 750 Bytes would result in a max space requirement of about 760KB.
 * - This cache is quickly emptied, but is not purged, so errors in Portmaster could result in dead entries.
 * Verdict cache:
 * - On entry has about 50 Bytes.
 * - A size of 1024 would result in a requirements of about 50KB which is allocated on initialization.
 * - This cache is not emptied or purged, it will pretty much always be at max capacity.
 */
#define PM_PACKET_CACHE_SIZE 1024
#define PM_VERDICT_CACHE_SIZE 1024

/*
 * Container for Verdicts
 */
typedef struct {
    UINT32 id;          //ID from RegisterPacket
    verdict_t verdict;
} PortmasterVerdictInfo;

/*
 * Container for Payload
 */
typedef struct {
    UINT32 id;
    UINT32 len;         // preset with maxlen of payload from caller -> set with actual len of payload from receiver
} PortmasterPayload;

typedef struct {
    UINT32 localIP[4];                  // Source Address, only srcIP[0] if IPv4
    UINT32 remoteIP[4];                 // Destination Address
    UINT16 localPort;                   // Source Port
    UINT16 remotePort;                  // Destination port
    UINT8 ipV6;                         // True: IPv6, False: IPv4
    UINT8 protocol;                     // Protocol (UDP, TCP, ...)
    verdict_t verdict;                  // New verdict
} VerdictUpdateInfo;

/*
 * Currently unused returncodes
 */
#define PM_STATUS_SUCCESS       0x00
#define PM_STATUS_BUF_TOO_SMALL 0x101
#define PM_STATUS_ID_NOT_FOUND  0x102
#define PM_STATUS_UNDEFINED     0x103
#define PM_STATUS_INTERNAL_ERROR 0x104

/*
 * Max size for getPayload function
 */
#define MAX_PAYLOAD_SIZE 1024*10

/****************************************************************************/
/* IOCTL declaration                                                        */
/****************************************************************************/

#define SIOCTL_TYPE 40000

#define IOCTL_VERSION \
    CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_SHUTDOWN_REQUEST \
    CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)  // Not used

#define IOCTL_RECV_VERDICT_REQ \
    CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_SET_VERDICT \
    CTL_CODE(SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_GET_PAYLOAD \
    CTL_CODE(SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_CLEAR_CACHE \
    CTL_CODE(SIOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_UPDATE_VERDICT \
    CTL_CODE(SIOCTL_TYPE, 0x806, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_GET_CONNECTIONS_STATS \
    CTL_CODE(SIOCTL_TYPE, 0x807, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

/****************************************************************************/
/* MISC                                                       */
/****************************************************************************/
#define IPv4_LOCALHOST_NET_MASK 0xFF000000
#define IPv4_LOCALHOST_NET 0x7F000000

#define IPv4_LOCALHOST_IP_NETWORK_ORDER 0x0100007f

#define IPv6_LOCALHOST_PART4               0x1
#define IPv6_LOCALHOST_PART4_NETWORK_ORDER 0x01000000

#define PORT_DNS 53
#define PORT_DNS_NBO 0x3500

#define PORT_PM_SPN_ENTRY 717
#define PORT_PM_SPN_ENTRY_NBO 0xCD02

#define PORT_PM_API 817

#define IPv4 4
#define IPv6 6

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
#define PROTOCOL_HOPOPT  0
#define PROTOCOL_ICMP    1
#define PROTOCOL_IGMP    2
#define PROTOCOL_IPv4    4
#define PROTOCOL_TCP     6
#define PROTOCOL_UDP     17
#define PROTOCOL_RDP     27
#define PROTOCOL_DCCP    33
#define PROTOCOL_IPv6    41
#define PROTOCOL_ICMPv6  58
#define PROTOCOL_UDPLite 136

#define ICMPV4_CODE_DESTINATION_UNREACHABLE 3
#define ICMPV4_CODE_DU_PORT_UNREACHABLE 3               // Destination Unreachable (Port unreachable) 
#define ICMPV4_CODE_DU_ADMINISTRATIVELY_PROHIBITED 13   // Destination Unreachable (Communication Administratively Prohibited) 

#define ICMPV6_CODE_DESTINATION_UNREACHABLE 1
#define ICMPV6_CODE_DU_PORT_UNREACHABLE 4               // Destination Unreachable (Port unreachable) 

#define DIRECTION_OUTBOUND 0
#define DIRECTION_INBOUND  1

#endif  // PM_COMMON_H
