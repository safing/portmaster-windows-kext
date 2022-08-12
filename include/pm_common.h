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

#ifndef portmaster_common_h
#define portmaster_common_h

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
} portmaster_packet_info, *pportmaster_packet_info;


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
} IPV4_HEADER, *PIPV4_HEADER;

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
} IPV6_HEADER, *PIPV6_HEADER;

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
} TCP_HEADER, *PTCP_HEADER;

/*
 * UDP Header.
 */
typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
} UDP_HEADER, *PUDP_HEADER;

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
#define VERDICT_NAMES { "PORTMASTER_VERDICT_ERROR",\
                        "PORTMASTER_VERDICT_GET",\
                        "PORTMASTER_VERDICT_ACCEPT",\
                        "PORTMASTER_VERDICT_BLOCK",\
                        "PORTMASTER_VERDICT_DROP",\
                        "PORTMASTER_VERDICT_REDIR_DNS",\
                        "PORTMASTER_VERDICT_REDIR_TUNNEL"}

/*
 * CACHE SIZES for packet and verdict cache
 * Packet cache:
 * - One entry can be as big as the MTU - eg. 1500 Bytes.
 * - But normally it will be much smaller, eg. a TCP SYN packet.
 * - A size of 512 with a mean entry size of 750 Bytes would result in a max space requirement of about 380KB.
 * - This cache is quickly emptied, but is not purged, so errors in Portmaster could result in dead entries.
 * Verdict cache:
 * - On entry has about 50 Bytes.
 * - A size of 1024 would result in a max space requirements of about 50KB.
 * - This cache is not emptied or purged, it will pretty much always be at max capacity.
 */
#define PM_PACKET_CACHE_SIZE 512
#define PM_VERDICT_CACHE_SIZE 1024

/*
 * Container for Verdicts
 */
typedef struct {
    UINT32 id;          //ID from RegisterPacket
    verdict_t verdict;
} portmaster_verdict_info, *pportmaster_verdict_info;

/*
 * Container for Payload
 */
typedef struct {
    UINT32 id;
    UINT32 len;         //preset with maxlen of payload from caller -> set with acutal len of payload from receiver
} portmaster_payload, *pportmaster_payload;


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

#define IOCTL_HELLO \
    CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)  //FILE_ANY_ACCESS

#define IOCTL_RECV_VERDICT_REQ_POLL \
    CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_RECV_VERDICT_REQ \
   CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_SET_VERDICT \
    CTL_CODE(SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_GET_PAYLOAD \
    CTL_CODE(SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_CLEAR_CACHE \
    CTL_CODE(SIOCTL_TYPE, 0x805, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

/****************************************************************************/
/* MISC                                                       */
/****************************************************************************/
#define IPv4_LOCALHOST_NET_MASK 0xFF000000
#define IPv4_LOCALHOST_NET 0x7F000000

#define IPv6_LOCALHOST_PART4 0x1

#define PORT_DNS 53
#define PORT_DNS_NBO 0x3500

#define PORT_PM_SPN_ENTRY 717
#define PORT_PM_SPN_ENTRY_NBO 0xCD02

#define PORT_PM_API 817

#endif  //Include Guard
