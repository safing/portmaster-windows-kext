/*
 *  Name:        pm_packet_utils.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Helper packet functions
 *
 *  Scope:       Kernelmode
 */

#include "pm_packet.h"
#include "pm_checksum.h"
#include "pm_netbuffer.h"
#include "pm_utils.h"
#include "pm_debug.h"

static size_t getTCPResetPacketSizeIPv4();
static size_t getTCPResetPacketSizeIPv6();
static size_t getICMPBlockedPacketSizeIPv4(void *originalPacket, size_t originalPacketLength);
static size_t getICMPBlockedPacketSizeIPv6(size_t originalPacketLength);

static void generateTCPResetPacketIPv4(void *originalPacket, size_t originalPacketLength, void *packet);
static void generateTCPResetPacketIPv6(void *originalPacket, size_t originalPacketLength, void *packet);
static void generateICMPBlockedPacketIPv4(void *originalPacket, size_t originalPacketLength, bool useLocalHost, void *icmpPacket);
static void generateICMPBlockedPacketIPv6(void *originalPacket, size_t originalPacketLength, bool useLocalHost, void *icmpPacket);

static NTSTATUS sendTCPResetPacket(PortmasterPacketInfo* packetInfo, void* originalPacket, size_t originalPacketLength);
static NTSTATUS sendICMPBlockedPacket(PortmasterPacketInfo* packetInfo, void* originalPacket, size_t originalPacketLength, bool useLocalHost);

static void freeAfterInject(void *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatch_level);

static HANDLE injectV4Handle = NULL;
static HANDLE injectV6Handle = NULL;

NTSTATUS initializeInjectHandles() {
     // Create the packet injection handles.
    NTSTATUS status = FwpsInjectionHandleCreate(AF_INET,
            FWPS_INJECTION_TYPE_NETWORK,
            &injectV4Handle);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create WFP in4 injection handle", status);
        return status;
    }

    status = FwpsInjectionHandleCreate(AF_INET6,
            FWPS_INJECTION_TYPE_NETWORK,
            &injectV6Handle);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create WFP in6 injection handle", status);
        return status;
    }

    return STATUS_SUCCESS;
}

void destroyInjectHandles() {
    if (injectV4Handle != NULL) {
        FwpsInjectionHandleDestroy(injectV4Handle);
        injectV4Handle = NULL;
    }

    if (injectV6Handle != NULL) {
        FwpsInjectionHandleDestroy(injectV6Handle);
        injectV6Handle = NULL;
    }
}

HANDLE getInjectionHandleForPacket(PortmasterPacketInfo *packetInfo) {
    if (packetInfo->ipV6 == 0) {
        return injectV4Handle;
    } else{
        return injectV4Handle;
    }
}

NTSTATUS injectPacket(PortmasterPacketInfo *packetInfo, UINT8 direction, void *packet, size_t packetLength) {
    // Create network buffer list for the packet
    PNET_BUFFER_LIST injectNBL = NULL;
    NTSTATUS status = wrapPacketDataInNB(packet, packetLength, &injectNBL);
    if (!NT_SUCCESS(status)) {
        ERR("wrap_packet_data_in_nb failed: %u", status);
        portmasterFree(packet);
        return status;
    }

    // get inject handle and check if packet is localhost
    bool isLoopback = isPacketLoopback(packetInfo);
    HANDLE handle = getInjectionHandleForPacket(packetInfo);

    // Inject packet. For localhost we must always send
    if (direction == DIRECTION_OUTBOUND || isLoopback) {
        status = FwpsInjectNetworkSendAsync(handle, NULL, 0,
                UNSPECIFIED_COMPARTMENT_ID, injectNBL, freeAfterInject,
                packet);
        INFO("InjectNetworkSend executed: %s", printPacketInfo(packetInfo));
    } else {
        status = FwpsInjectNetworkReceiveAsync(handle, NULL, 0,
                UNSPECIFIED_COMPARTMENT_ID, packetInfo->interfaceIndex,
                packetInfo->subInterfaceIndex, injectNBL, freeAfterInject,
                packet);
        INFO("InjectNetworkReceive executed: %s", printPacketInfo(packetInfo));
    }

    if (!NT_SUCCESS(status)) {
        freeAfterInject(packet, injectNBL, false);
    }
    return status;
}

void copyAndInject(PortmasterPacketInfo* packetInfo, PNET_BUFFER nb, UINT32 ipHeaderSize) {
    NTSTATUS status = STATUS_SUCCESS;

    // Retreat buffer data start for inbound packet.
    if (packetInfo->direction == DIRECTION_INBOUND) {
        status = NdisRetreatNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
        if (!NT_SUCCESS(status)) {
            ERR("copyAndInject > failed to retreat net buffer data start");
            return;
        }
    }

    // Copy the packet data.
    void* packet = NULL;
    size_t packetLength = 0;
    status = copyPacketDataFromNB(nb, 0, &packet, &packetLength);
    if (!NT_SUCCESS(status)) {
        ERR("copyAndInject > copy_packet_data_from_nb failed: %d", status);
        return;
    }

    // Advance data start back to original position.
    if (packetInfo->direction == DIRECTION_INBOUND) {
        NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
    }

    // Fix checksums, including TCP/UDP.
    if (!packetInfo->ipV6) {
        calcIPv4Checksum(packet, packetLength, true);
    } else {
        calcIPv6Checksum(packet, packetLength, true);
    }

    status = injectPacket(packetInfo, packetInfo->direction, packet, packetLength); // this call will free the packet even if the inject fails

    if (!NT_SUCCESS(status)) {
        ERR("copyAndInject -> FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
    }
}

static size_t getTCPResetPacketSizeIPv4() {
    return sizeof(IPv4Header) + sizeof(TCPHeader);
}

static size_t getTCPResetPacketSizeIPv6() {
    return sizeof(IPv6Header) + sizeof(TCPHeader);
}

static void generateTCPResetPacketIPv4(void *originalPacket, size_t originalPacketLength, void *tcpResetPacket) {

    // Initialize header for the original packet with SYN flag
    size_t originalIPHeaderLength = calcIPv4HeaderSize(originalPacket, originalPacketLength);
    IPv4Header *originalIPHeader = (IPv4Header*) originalPacket;
    TCPHeader *originalTCPHeader = (TCPHeader*) ((UINT8*)originalPacket + originalIPHeaderLength);
    size_t packetLength = getTCPResetPacketSizeIPv4();

    // initialize IPv4 header
    IPv4Header *ipHeader = (IPv4Header*) tcpResetPacket;
    ipHeader->HdrLength = sizeof(IPv4Header) / 4;
    ipHeader->Version = IPv4;
    ipHeader->TOS = 0;
    ipHeader->Length = RtlUshortByteSwap(packetLength);
    ipHeader->Id = 0;
    ipHeader->Protocol = PROTOCOL_TCP;
    ipHeader->TTL = 128;
    ipHeader->DstAddr = originalIPHeader->SrcAddr; // Source becomes destination
    ipHeader->SrcAddr = originalIPHeader->DstAddr; // Destination becomes source

        // Initialize TCP header
    TCPHeader *tcpHeader = (TCPHeader*) ((UINT8*)tcpResetPacket + sizeof(IPv4Header));
    tcpHeader->SrcPort = originalTCPHeader->DstPort; // Source becomes destination
    tcpHeader->DstPort = originalTCPHeader->SrcPort; // Destination becomes source
    tcpHeader->HdrLength = sizeof(TCPHeader) / 4;
    tcpHeader->SeqNum = 0;
    // We should acknowledge the SYN packet while doing the reset
    tcpHeader->AckNum = RtlUlongByteSwap(RtlUlongByteSwap(originalTCPHeader->SeqNum) + 1);
    tcpHeader->Ack = 1;
    tcpHeader->Rst = 1;

    calcIPv4Checksum(tcpResetPacket, packetLength, true);
}

static void generateTCPResetPacketIPv6(void *originalPacket, size_t originalPacketLength, void *tcpResetPacket) {
    // Initialize header for the original packet with SYN flag
    size_t originalIPHeaderLength = calcIPv6HeaderSize(originalPacket, originalPacketLength, NULL);
    IPv6Header *originalIPHeader = (IPv6Header*) originalPacket;
    TCPHeader *originalTCPHeader = (TCPHeader*) ((UINT8*)originalPacket + originalIPHeaderLength);

    // allocate memory for the reset packet
    size_t packetLength = getTCPResetPacketSizeIPv6();

    // initialize IPv6 header
    IPv6Header *ipHeader = (IPv6Header*) tcpResetPacket;
    ipHeader->Version = IPv6;
    ipHeader->Length = sizeof(TCPHeader);
    ipHeader->NextHdr = PROTOCOL_TCP;
    ipHeader->HopLimit = 128;
    RtlCopyMemory(ipHeader->DstAddr, originalIPHeader->SrcAddr, sizeof(originalIPHeader->SrcAddr)); // Source becomes destination
    RtlCopyMemory(ipHeader->SrcAddr, originalIPHeader->DstAddr, sizeof(originalIPHeader->DstAddr)); // Destination becomes source

    // Initialize TCP header
    TCPHeader *tcpHeader = (TCPHeader*) ((UINT8*)tcpResetPacket + sizeof(IPv6Header));
    tcpHeader->SrcPort = originalTCPHeader->DstPort; // Source becomes destination
    tcpHeader->DstPort = originalTCPHeader->SrcPort; // Destination becomes source
    tcpHeader->HdrLength = sizeof(TCPHeader) / 4;
    tcpHeader->SeqNum = 0;
    // We should acknowledge the SYN packet while doing the reset
    tcpHeader->AckNum = RtlUlongByteSwap(RtlUlongByteSwap(originalTCPHeader->SeqNum) + 1);
    tcpHeader->Ack = 1;
    tcpHeader->Rst = 1;

    calcIPv6Checksum(tcpResetPacket, packetLength, true);
}

static size_t getICMPBlockedPacketSizeIPv4(void* originalPacket, size_t originalPacketLength) {
    size_t originalIPHeaderLength = calcIPv4HeaderSize(originalPacket, originalPacketLength);
    // ICMP body is the original packet IP header + first 64bits (8 bytes) of the body https://www.rfc-editor.org/rfc/rfc792
    UINT16 bytesToCopyFromOriginalPacket = (UINT16)originalIPHeaderLength + 8;
    // Check if the body is less then 8 bytes
    if(bytesToCopyFromOriginalPacket < originalPacketLength) {
        bytesToCopyFromOriginalPacket = (UINT16)originalPacketLength;
    }

    UINT16 headerLength = sizeof(IPv4Header) + sizeof(ICMPHeader);
    UINT16 packetLength = headerLength + bytesToCopyFromOriginalPacket;

    return packetLength;
}

static void generateICMPBlockedPacketIPv4(void* originalPacket, size_t originalPacketLength, bool useLocalHost, void *icmpPacket) {
    // Initialize header for the original UDP packet
    IPv4Header* originalIPHeader = (IPv4Header*) originalPacket;

    // Initialize variables
    UINT16 headerLength = sizeof(IPv4Header) + sizeof(ICMPHeader);
    UINT16 packetLength = (UINT16)getICMPBlockedPacketSizeIPv4(originalPacket, originalPacketLength);
    UINT16 bytesToCopyFromOriginalPacket = packetLength - headerLength;

    // Initialize IPv4 header
    IPv4Header *ipHeader = (IPv4Header*) icmpPacket;
    ipHeader->HdrLength = sizeof(IPv4Header) / 4;
    ipHeader->Version = IPv4;
    ipHeader->TOS = 0;
    ipHeader->Length = RtlUshortByteSwap(packetLength);
    ipHeader->Id = 0;
    ipHeader->Protocol = PROTOCOL_ICMP;
    ipHeader->TTL = 128;

    // Use localhost as source and destination to bypass the Windows firewall
    if(useLocalHost) {
        ipHeader->SrcAddr = IPv4_LOCALHOST_IP_NETWORK_ORDER; // loopback address 127.0.0.1
        ipHeader->DstAddr = IPv4_LOCALHOST_IP_NETWORK_ORDER; // loopback address 127.0.0.1
    } else {
        ipHeader->SrcAddr = originalIPHeader->DstAddr; // Source becomes destination
        ipHeader->DstAddr = originalIPHeader->SrcAddr; // Destination becomes source
    }

    ICMPHeader *icmpHeader = (ICMPHeader*) ((UINT8*)icmpPacket + sizeof(IPv4Header));
    icmpHeader->Type = ICMPV4_CODE_DESTINATION_UNREACHABLE;
    icmpHeader->Code = ICMPV4_CODE_DE_PORT_UNREACHABLE; // the only code that closes the UDP connection on Windows 10.

    // Calculate checksum for the original packet and copy it in the icmp body.
    calcIPv4Checksum(originalPacket, originalPacketLength, true);
    RtlCopyMemory(((UINT8*)icmpHeader + sizeof(ICMPHeader)), originalPacket, bytesToCopyFromOriginalPacket);

    // Calculate checksum for the icmp packet
    calcIPv4Checksum(icmpPacket, packetLength, true);
}

static size_t getICMPBlockedPacketSizeIPv6(size_t originalPacketLength) {
    UINT16 bytesToCopyFromOriginalPacket = (UINT16)originalPacketLength;
    UINT16 headerLength = sizeof(IPv6Header) + sizeof(ICMPHeader);
    UINT16 packetLength = headerLength + bytesToCopyFromOriginalPacket;
    // Check if the packet exceeds the minimum MTU.
    // The body of the ICMPv6: As much of invoking packet as possible without the ICMPv6 packet exceeding the minimum IPv6 MTU https://www.rfc-editor.org/rfc/rfc4443#section-3.1
    // IPv6 requires that every link in the internet have an MTU of 1280 octets or greater https://www.ietf.org/rfc/rfc2460.txt -> 5. Packet Size Issues.
    if(packetLength > 1280) {
        bytesToCopyFromOriginalPacket = 1280 - headerLength;
        packetLength = headerLength + bytesToCopyFromOriginalPacket;
    }

    return packetLength;
}

static void generateICMPBlockedPacketIPv6(void* originalPacket, size_t originalPacketLength, bool useLocalHost, void *icmpPacket) {
    // Initialize header for the original packet
    IPv6Header *originalIPHeader = (IPv6Header*) originalPacket;
    
    // Calculate length variables
    UINT16 headerLength = sizeof(IPv6Header) + sizeof(ICMPHeader);
    UINT16 packetLength = (UINT16)getICMPBlockedPacketSizeIPv6(originalPacketLength);
    UINT16 bytesToCopyFromOriginalPacket = packetLength - headerLength;

    // Initialize IPv6 header
    IPv6Header *ipHeader = (IPv6Header*) icmpPacket;
    ipHeader->Version = IPv6;
    ipHeader->Length = sizeof(ICMPHeader) + bytesToCopyFromOriginalPacket;
    ipHeader->NextHdr = PROTOCOL_ICMPv6;
    ipHeader->HopLimit = 128;

    // Use localhost as source and destination to bypass the windows firewall.
    if(useLocalHost) {
        ipHeader->SrcAddr[3] = IPv6_LOCALHOST_PART4_NETWORK_ORDER; // loopback address ::1
        ipHeader->DstAddr[3] = IPv6_LOCALHOST_PART4_NETWORK_ORDER; // loopback address ::1
    } else {
        RtlCopyMemory(ipHeader->SrcAddr, originalIPHeader->DstAddr, sizeof(originalIPHeader->SrcAddr)); // Source becomes destination.
        RtlCopyMemory(ipHeader->DstAddr, originalIPHeader->SrcAddr, sizeof(originalIPHeader->DstAddr)); // Destination becomes source.
    }

    ICMPHeader *icmpHeader = (ICMPHeader*) ((UINT8*)icmpPacket + sizeof(IPv6Header));
    icmpHeader->Type = ICMPV6_CODE_DESTINATION_UNREACHABLE;
    icmpHeader->Code = ICMPV6_CODE_DE_PORT_UNREACHABLE; // the only code that closes the UDP connection on Windows 10.

    // Calculate checksum for the original packet and copy it in the icmp body.
    calcIPv6Checksum(originalPacket, originalPacketLength, true);
    RtlCopyMemory((UINT8*)icmpHeader + sizeof(ICMPHeader), originalPacket, bytesToCopyFromOriginalPacket);

    // Calculate checksum for the icmp packet
    calcIPv6Checksum(icmpPacket, packetLength, true);
}


static NTSTATUS sendICMPBlockedPacket(PortmasterPacketInfo* packetInfo, void* originalPacket, size_t originalPacketLength, bool useLocalHost) {
    // Only UDP is supported
    if(packetInfo->protocol != PROTOCOL_UDP) {
        return STATUS_NOT_SUPPORTED; // Not UDP
    }

    size_t packetLength = 0;
    void *icmpPacket = NULL;

    if(packetInfo->ipV6) {
        packetLength = getICMPBlockedPacketSizeIPv6(originalPacketLength);
        icmpPacket = portmasterMalloc(packetLength, false);
        generateICMPBlockedPacketIPv6(packetInfo, originalPacketLength, useLocalHost, icmpPacket);
    } else {
        packetLength = getICMPBlockedPacketSizeIPv4(originalPacket, originalPacketLength);
        icmpPacket = portmasterMalloc(packetLength, false);
        generateICMPBlockedPacketIPv4(packetInfo, originalPacketLength, useLocalHost, icmpPacket);
    }

     // Reverse direction and inject packet
    UINT8 injectDirection = packetInfo->direction == DIRECTION_INBOUND ? DIRECTION_OUTBOUND : DIRECTION_INBOUND;
    NTSTATUS status = injectPacket(packetInfo, injectDirection, icmpPacket, packetLength); // this call will free the packet even if the inject fails

    if (!NT_SUCCESS(status)) {
        ERR("sendICMPBlockedPacket ipv6 -> FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
    }

    return status;
}

static NTSTATUS sendTCPResetPacket(PortmasterPacketInfo* packetInfo, void* originalPacket, size_t originalPacketLength) {
    // Only TCP is supported
    if(packetInfo->protocol != PROTOCOL_TCP) {
        return STATUS_NOT_SUPPORTED; // Not TCP
    }

    size_t packetLength = 0;
    void *tcpResetPacket = NULL;

    // Generate reset packet
    if(packetInfo->ipV6) {
        packetLength = getTCPResetPacketSizeIPv6();
        tcpResetPacket = portmasterMalloc(packetLength, false);
        generateTCPResetPacketIPv6(originalPacket, originalPacketLength, tcpResetPacket);
    } else {
        packetLength = getTCPResetPacketSizeIPv4();
        tcpResetPacket = portmasterMalloc(packetLength, false);
        generateTCPResetPacketIPv4(originalPacket, originalPacketLength, tcpResetPacket);
    }

    // Reverse direction and inject packet
    UINT8 injectDirection = packetInfo->direction == DIRECTION_INBOUND ? DIRECTION_OUTBOUND : DIRECTION_INBOUND;
    NTSTATUS status = injectPacket(packetInfo, injectDirection, tcpResetPacket, packetLength); // this call will free the packet even if the inject fails

    if(!NT_SUCCESS(status)) {
        ERR("send_icmp_blocked_packet ipv4 -> FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
    }

    return status;
}

NTSTATUS sendBlockPacket(PortmasterPacketInfo* packetInfo, void* originalPacket, size_t originalPacketLength) {
    if(packetInfo->protocol == PROTOCOL_TCP) {
        return sendTCPResetPacket(packetInfo, originalPacket, originalPacketLength);
    } else { // Everything else
        return sendICMPBlockedPacket(packetInfo, originalPacket, originalPacketLength, true);
    }
}

NTSTATUS sendBlockPacketFromCallout(PortmasterPacketInfo* packetInfo, PNET_BUFFER nb, size_t ipHeaderSize) {
    NTSTATUS status = STATUS_SUCCESS;

    if (!packetInfo || !nb || ipHeaderSize == 0) {
        ERR("Invalid parameters");
        return status;
    }

    // Inbound traffic requires special treatment - dafuq?
    if (packetInfo->direction == DIRECTION_INBOUND) {
        status = NdisRetreatNetBufferDataStart(nb, (ULONG)ipHeaderSize, 0, NULL);
        if (!NT_SUCCESS(status)) {
            ERR("failed to retreat net buffer data start");
            return status;
        }
    }

    // Create new Packet -> wrap it in new nb, so we don't need to shift this nb back.
    void* packet = NULL;
    size_t packetLength = 0;
    status = copyPacketDataFromNB(nb, 0, &packet, &packetLength);
    if (!NT_SUCCESS(status)) {
        ERR("copyPacketDataFromNB 3: %d", status);
        return status;
    }
    // Now data should contain a full blown packet

    // In order to be as clean as possible, we shift back nb, even though it may not be necessary.
    if (packetInfo->direction == DIRECTION_INBOUND) {
        NdisAdvanceNetBufferDataStart(nb, (ULONG)ipHeaderSize, 0, NULL);
    }

    // Now we can send the RST (for TCP) or ICMP (for UDP) packet
    status = sendBlockPacket(packetInfo, packet, packetLength);
    portmasterFree(packet);
    return status;
}

void redirectPacket(PortmasterPacketInfo *packetInfo, PortmasterPacketInfo *redirInfo, void *packet, size_t packetLength, bool dns) {    
    // sanity check
    if (!packetInfo || !redirInfo || !packet || packetLength == 0) {
        ERR("Invalid parameters");
        return;
    }

    INFO("About to modify headers for %s", printPacketInfo(packetInfo));
    INFO("Packet starts at 0p%p with %u bytes", packet, packetLength);

    // Modify headers
    if (packetInfo->ipV6 == 0) { // IPv4
        size_t ipHeaderLength = calcIPv4HeaderSize(packet, packetLength);
        if (ipHeaderLength > 0) { // IPv4 Header
            IPv4Header *ipHeader = (IPv4Header*) packet;

            if (packetInfo->direction == DIRECTION_OUTBOUND) {
                ipHeader->DstAddr = RtlUlongByteSwap(packetInfo->localIP[0]);
                // IP_LOCALHOST is rejected by Windows Networkstack (nbl-status 0xc0000207, "STATUS_INVALID_ADDRESS_COMPONENT"
                // Problem might be switching Network scope from "eth0" to "lo"
                // Instead, just redir to the address the packet came from
            } else {
                ipHeader->SrcAddr = RtlUlongByteSwap(redirInfo->remoteIP[0]);
            }

            // TCP
            if (ipHeader->Protocol == PROTOCOL_TCP && packetLength >= ipHeaderLength + 20 /* TCP Header */) {
                TCPHeader *tcpHeader = (TCPHeader*) ((UINT8*)packet + ipHeaderLength);

                if (packetInfo->direction == DIRECTION_OUTBOUND) {
                    if (dns) {
                        tcpHeader->DstPort = PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        tcpHeader->DstPort = PORT_PM_SPN_ENTRY_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    tcpHeader->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

            // UDP
            } else if (ipHeader->Protocol == PROTOCOL_UDP && packetLength >= ipHeaderLength + 8 /* UDP Header */) {
                UDPHeader *udpHeader = (UDPHeader*) ((UINT8*)packet + ipHeaderLength);

                if (packetInfo->direction == DIRECTION_OUTBOUND) {
                    if (dns) {
                        udpHeader->DstPort = PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        udpHeader->DstPort = PORT_PM_SPN_ENTRY_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    udpHeader->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

            } else {  //Neither UDP nor TCP -> We can only redirect UDP or TCP -> drop the rest
                portmasterFree(packet);
                WARN("Portmaster issued redirect for Non UDP or TCP Packet:");
                WARN("%s", printPacketInfo(packetInfo));
                return;
            }
        } else { // not enough data for IPv4 Header
            portmasterFree(packet);
            WARN("IPv4 Packet too small:");
            WARN("%s", printPacketInfo(packetInfo));
            return;
        }
    } else { // IPv6
        size_t ipHeaderLength = calcIPv6HeaderSize(packet, packetLength, NULL);
        if (ipHeaderLength > 0) { // IPv6 Header
            IPv6Header *ipHeader = (IPv6Header*) packet;


            if (packetInfo->direction == DIRECTION_OUTBOUND) {
                for (int i = 0; i < 4; i++) {
                    ipHeader->DstAddr[i]= RtlUlongByteSwap(packetInfo->localIP[i]);
                }
                // IP_LOCALHOST is rejected by Windows Networkstack (nbl-status 0xc0000207, "STATUS_INVALID_ADDRESS_COMPONENT"
                // Problem might be switching Network scope from "eth0" to "lo"
                // Instead, just redir to the address the packet came from
            } else {
                for (int i = 0; i < 4; i++) {
                    ipHeader->SrcAddr[i]= RtlUlongByteSwap(redirInfo->remoteIP[i]);
                }
            }

            // TCP
            if (ipHeader->NextHdr == PROTOCOL_TCP && packetLength >= ipHeaderLength + 20 /* TCP Header */) {
                TCPHeader* tcpHeader = (TCPHeader*) ((UINT8*)packet + ipHeaderLength);

                if (packetInfo->direction == DIRECTION_OUTBOUND) {
                    if (dns) {
                        tcpHeader->DstPort= PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        tcpHeader->DstPort= PORT_PM_SPN_ENTRY_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    tcpHeader->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

                // UDP
            } else if (ipHeader->NextHdr == PROTOCOL_UDP && packetLength >= ipHeaderLength + 8 /* UDP Header */) {
                UDPHeader* udpHeader = (UDPHeader*) ((UINT8*)packet + ipHeaderLength);

                if (packetInfo->direction == DIRECTION_OUTBOUND) {
                    if (dns) {
                        udpHeader->DstPort= PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        udpHeader->DstPort= PORT_PM_SPN_ENTRY_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    udpHeader->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

            } else {  // Neither UDP nor TCP -> We can only redirect UDP or TCP -> drop the rest
                portmasterFree(packet);
                WARN("Portmaster issued redirect for Non UDP or TCP Packet:");
                WARN("%s", printPacketInfo(packetInfo));
                return;
            }
        } else { // not enough data for IPv6 Header
            portmasterFree(packet);
            WARN("IPv6 Packet too small:");
            WARN("%s", printPacketInfo(packetInfo));
            return;
        }
    }
    INFO("Headers modified");

    // Fix checksums, including TCP/UDP.
    if (!packetInfo->ipV6) {
        calcIPv4Checksum(packet, packetLength, true);
    } else {
        calcIPv6Checksum(packet, packetLength, true);
    }

    // re-inject ...

    // Reset routing compartment ID, as we are changing where this is going to.
    // This necessity is unconfirmed.
    // Experience shows that using the compartment ID can sometimes cause errors.
    // It seems safer to always use UNSPECIFIED_COMPARTMENT_ID.
    // packetInfo->compartmentId = UNSPECIFIED_COMPARTMENT_ID;
    NTSTATUS status = injectPacket(packetInfo, packetInfo->direction, packet, packetLength); // this call will free the packet even if the inject fails

    if (!NT_SUCCESS(status)) {
        ERR("redir -> FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
    }
}

void redirectPacketFromCallout(PortmasterPacketInfo *packetInfo, PortmasterPacketInfo *redirInfo, PNET_BUFFER nb, size_t ipHeaderSize, bool dns) {
    // sanity check
    if (!redirInfo) {
        ERR("redirInfo is NULL!");
    }
    if (!packetInfo || !redirInfo || !nb || ipHeaderSize == 0) {
        ERR("Invalid parameters");
        return;
    }

    // DEBUG: print its TCP 4-tuple
    INFO("Handling redir for %s", printPacketInfo(packetInfo));

    //Inbound traffic requires special treatment - dafuq?
    if (packetInfo->direction == DIRECTION_INBOUND) {
        NTSTATUS status = NdisRetreatNetBufferDataStart(nb, (ULONG)ipHeaderSize, 0, NULL);
        if (!NT_SUCCESS(status)) {
            ERR("failed to retreat net buffer data start");
            return;
        }
    }

    //Create new Packet -> wrap it in new nb, so we don't need to shift this nb back.
    size_t packetLength = 0;
    void* packet = NULL;
    NTSTATUS status = copyPacketDataFromNB(nb, 0, &packet, &packetLength);
    if (!NT_SUCCESS(status)) {
        ERR("copy_packet_data_from_nb 3: %d", status);
        return;
    }
    //Now data should contain a full blown packet

    // In order to be as clean as possible, we shift back nb, even though it may not be necessary.
    if (packetInfo->direction == DIRECTION_INBOUND) {
        NdisAdvanceNetBufferDataStart(nb, (ULONG)ipHeaderSize, 0, NULL);
    }
    redirectPacket(packetInfo, redirInfo, packet, packetLength, dns);

}

static void freeAfterInject(void *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatch_level) {
    UNREFERENCED_PARAMETER(dispatch_level);

    // Sanity check.
    if (!nbl) {
        ERR("Invalid parameters");
        return;
    }

#ifdef DEBUG_ON
    // Check for NBL errors.
    {
        NDIS_STATUS status;
        status = NET_BUFFER_LIST_STATUS(nbl);
        if (status == STATUS_SUCCESS) {
            INFO("injection success: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), printIpv4Packet(context));
        } else {
            // Check here for status codes: http://errorco.de/win32/ntstatus-h/
            ERR("injection failure: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), printIpv4Packet(context));
        }
    }
#endif // DEBUG

    // Free allocated NBL/Mdl memory.
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    PMDL mdl = NET_BUFFER_FIRST_MDL(nb);
    IoFreeMdl(mdl);
    FwpsFreeNetBufferList(nbl);

    // Free packet, which is passed as context.
    if (context != NULL) {
        portmasterFree(context);
    }
}
