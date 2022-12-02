/*
 *  Name:        pm_checksum.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation for checksum calculations in order
 *               to modify and reinject IP Packets
 *
 *  Scope:       Kernelmode
 */

#define LOGGER_NAME "pm_checksum"
#include "pm_checksum.h"
#include "pm_common.h"

static UINT32 checksumAdd(void* data, size_t length) {
    UINT16 *data16 = (UINT16*) data;
    size_t length16 = length/2;

    UINT32 sum = 0;
    
    // sum two bytes at once
    for (size_t i = 0; i < length16; i++) {
        // fprintf(stderr, "adding: 0x%x\n", data16[i]);
        sum += data16[i];
    }

    // sum single byte left over
    if (length & 0x1) {
        UINT8 *data8 = (UINT8*) data;
        sum += data8[length-1];
    }

    return sum;
}

static UINT16 checksumFinish(UINT32 sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    return (UINT16) sum;
}

VOID calcIPv4Checksum(void *data, size_t length, bool calcTransport) {
    size_t ipHeaderLength = calcIPv4HeaderSize(data, length);

    // sanity check
    if (!data || length == 0) {
        ERR("Invalid parameters");
        return;
    }

    if (ipHeaderLength > 0) {
        // calc IPv4 Header checksum
        IPv4Header *ipHeader = (IPv4Header*) data;

        ipHeader->Checksum = 0; // reset checksum
        UINT32 sum = checksumAdd((void*) data, ipHeaderLength); // calc on complete header
        ipHeader->Checksum = checksumFinish(sum); // finish calc

        INFO("calculated checksum: 0x%04X (NetworkByteorder), 0x%02X%02X", ipHeader->Checksum, ipHeader->Checksum&0x00FF, (ipHeader->Checksum&0xFF00)>>8);

        if (calcTransport) {
            if (ipHeader->Protocol == 6 || ipHeader->Protocol == 17) {
                // reset sum
                sum = 0;

                // pseudo header
                sum += checksumAdd((void*) &ipHeader->SrcAddr, 8); // src, dst address
                sum += ipHeader->Protocol << 8; // zero byte + protocol in network order
                sum += ipHeader->Length - (UINT32)(ipHeaderLength << 8); // payload length in network order

                // TCP
                if (ipHeader->Protocol == 6 && length >= ipHeaderLength + 20 /* TCP Header */) {
                    TCPHeader *tcpHeader = (TCPHeader*) ((UINT8*)data + ipHeaderLength);

                    tcpHeader->Checksum = 0;
                    sum += checksumAdd((void*) tcpHeader, length - ipHeaderLength);
                    tcpHeader->Checksum = checksumFinish(sum);

                    // UDP
                } else if (ipHeader->Protocol == 17 && length >= ipHeaderLength + 8 /* UDP Header */) {
                    UDPHeader *udpHeader = (UDPHeader*) ((UINT8*)data + ipHeaderLength);

                    udpHeader->Checksum = 0;
                    sum += checksumAdd((void*) udpHeader, length - ipHeaderLength);
                    udpHeader->Checksum = checksumFinish(sum);

                    // special case for UDP
                    if (udpHeader->Checksum == 0) {
                        udpHeader->Checksum = 0xFFFF;
                    }
                }
            // ICMP
            } else if (ipHeader->Protocol == 1 && length > ipHeaderLength + sizeof(ICMPHeader)) {
                ICMPHeader *icmpHeader = (ICMPHeader*) ((UINT8*)data + ipHeaderLength);

                sum = 0;
                icmpHeader->Checksum = 0;
                sum = checksumAdd((void*) icmpHeader, length - ipHeaderLength);
                icmpHeader->Checksum = checksumFinish(sum);
            }
        }
    }
}

void calcIPv6Checksum(void* data, size_t length, bool calcTransport) {
    UINT8 protocol;
    size_t ipHeaderLength = calcIPv6HeaderSize(data, length, &protocol);

    // sanity check
    if (!data || length == 0) {
        ERR("Invalid parameters");
        return;
    }

    if (ipHeaderLength > 0 && calcTransport && (protocol == 6 || protocol == 17 || protocol == 58)) {
        IPv6Header *ipHeader = (IPv6Header*) data;
        UINT32 payloadLength = (UINT32)(length - ipHeaderLength);

        // pseudo header
        // src, dst address
        UINT32 sum = checksumAdd((void*) &ipHeader->SrcAddr, 32);
        // payload length in network order
        sum += (payloadLength & 0xFF000000) >> 8;
        sum += (payloadLength & 0x00FF0000) << 8;
        sum += (payloadLength & 0x0000FF00) >> 8;
        sum += (payloadLength & 0x000000FF) << 8;
        sum = (sum & 0xFFFF) + (sum >> 16);
        // zero byte + protocol in network order
        sum += protocol << 8;

        // TCP
        if (protocol == 6 && length >= ipHeaderLength + 20 /* TCP Header */) {
            TCPHeader *tcpHeader = (TCPHeader*) ((UINT8*)data + ipHeaderLength);

            tcpHeader->Checksum = 0;
            sum += checksumAdd((void*) tcpHeader, length - ipHeaderLength);
            tcpHeader->Checksum = checksumFinish(sum);

            // UDP
        } else if (protocol == 17 && length >= ipHeaderLength + 8 /* UDP Header */) {
            UDPHeader *udpHeader = (UDPHeader*) ((UINT8*)data + ipHeaderLength);

            udpHeader->Checksum = 0;
            sum += checksumAdd((void*) udpHeader, length - ipHeaderLength);
            udpHeader->Checksum = checksumFinish(sum);

            // special case for UDP
            if (udpHeader->Checksum == 0) {
                udpHeader->Checksum = 0xFFFF;
            }
        // ICMPv6
        }  else if(protocol == 58 && length > ipHeaderLength + sizeof(ICMPHeader)) {
            ICMPHeader *icmpHeader = (ICMPHeader*) ((UINT8*)data + ipHeaderLength);

            icmpHeader->Checksum = 0;
            sum += checksumAdd((void*) icmpHeader, length - ipHeaderLength);
            icmpHeader->Checksum = checksumFinish(sum);
        }
    }
}

size_t calcIPv4HeaderSize(void* data, size_t length) {

    // sanity check
    if (!data || length == 0) {
        ERR("Invalid parameters");
        return 0;
    }

    if (length >= 20) {
        // calc IPv4 Header length
        IPv4Header *ipHeader = (IPv4Header*) data;
        size_t ipHeaderLength = (size_t)ipHeader->HdrLength * 4;
        if (length < ipHeaderLength) {
            WARN("Invalid Packet len=%u, ipHeaderLength=%u, ipHeader->HdrLength=0x%X", length, ipHeaderLength, ipHeader->HdrLength);
            return 0;
        }
        return ipHeaderLength;
    }
    WARN("Invalid Packet length=%u < 20", length);
    return 0;
}

size_t calcIPv6HeaderSize(void* data, size_t length, UINT8* returnProtocol) {

    // sanity check
    if (!data || length == 0) {
        ERR("Invalid parameters");
        return 0;
    }

    if (length >= 40) {
        IPv6Header *ipHeader = (IPv6Header*) data;
        int ipHeaderLength = 40;
        UINT8 *data8 = (UINT8*) data;
        UINT8 protocol;

        if (length < (size_t)ipHeaderLength) {
            return 0;
        }
        protocol = ipHeader->NextHdr;

        for (;;) {
            switch (protocol) {
                case 0:
                case 43:
                case 44:
                case 50:
                case 51:
                case 60:
                case 135:
                case 139:
                case 140:
                case 253:
                case 254:
                    if (length < (size_t)ipHeaderLength + 8) {
                        return 0;
                    }
                    protocol = data8[ipHeaderLength];
                    ipHeaderLength += 8 + data8[ipHeaderLength + 1] * 8;
                    if (length < (size_t)ipHeaderLength) {
                        return 0;
                    }
                    break;
                default:
                    if (returnProtocol != NULL) {
                        *returnProtocol = protocol;
                    }
                    return ipHeaderLength;
            }
        }
    }
    return 0;
}
