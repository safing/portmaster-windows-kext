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

UINT32 checksum_add(void* data, int len) {
    UINT16* data16 = (UINT16*) data;
    int len16 = len/2;

    UINT32 sum = 0;
    int i;

    // sum two bytes at once
    for (i = 0; i < len16; i++) {
        // fprintf(stderr, "adding: 0x%x\n", data16[i]);
        sum += data16[i];
    }

    // sum single byte left over
    if (len & 1) {
        UINT8* data8 = (UINT8*) data;
        sum += data8[len-1];
    }

    return sum;
}

UINT16 checksum_finish(UINT32 sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = ~sum;
    return (UINT16) sum;
}

VOID calc_ipv4_checksum(void* data, int len, BOOL calc_transport) {
    int ip_header_len = calc_ipv4_header_size(data, len);

    // sanity check
    if (!data || len == 0) {
        ERR("Invalid parameters");
        return;
    }

    if (ip_header_len > 0) {
        // calc IPv4 Header checksum
        PIPV4_HEADER ip_header = (PIPV4_HEADER) data;
        UINT32 sum = 0;

        ip_header->Checksum = 0; // reset checksum
        sum += checksum_add((void*) data, ip_header_len); // calc on complete header
        ip_header->Checksum = checksum_finish(sum); // finish calc

        INFO("calculated checksum: 0x%04X (NetworkByteorder), 0x%02X%02X", ip_header->Checksum, ip_header->Checksum&0x00FF, (ip_header->Checksum&0xFF00)>>8);

        if (calc_transport) {
            // reset sum
            sum = 0;

            // pseudo header
            sum += checksum_add((void*) &ip_header->SrcAddr, 8); // src, dst address
            sum += ip_header->Protocol<<8; // zero byte + protocol in network order
            sum += ip_header->Length - (ip_header_len<<8); // payload length in network order

            // TCP
            if (ip_header->Protocol == 6 && len >= ip_header_len + 20 /* TCP Header */) {
                PTCP_HEADER tcp_header = (PTCP_HEADER) ((UINT8*)data + ip_header_len);

                tcp_header->Checksum = 0;
                sum += checksum_add((void*) tcp_header, len - ip_header_len);
                tcp_header->Checksum = checksum_finish(sum);

                // UDP
            } else if (ip_header->Protocol == 17 && len >= ip_header_len + 8 /* UDP Header */) {
                PUDP_HEADER udp_header = (PUDP_HEADER) ((UINT8*)data + ip_header_len);

                udp_header->Checksum = 0;
                sum += checksum_add((void*) udp_header, len - ip_header_len);
                udp_header->Checksum = checksum_finish(sum);

                // special case for UDP
                if (udp_header->Checksum == 0) {
                    udp_header->Checksum = 0xFFFF;
                }

            }
        }
    }
}

VOID calc_ipv6_checksum(void* data, int len, BOOL calc_transport) {
    UINT8 protocol;
    int ip_header_len = calc_ipv6_header_size(data, len, &protocol);

    // sanity check
    if (!data || len == 0) {
        ERR("Invalid parameters");
        return;
    }

    if (ip_header_len > 0 && calc_transport) {
        PIPV6_HEADER ip_header = (PIPV6_HEADER) data;
        UINT32 sum = 0;
        UINT32 payload_len = len - ip_header_len;

        // pseudo header
        // src, dst address
        sum += checksum_add((void*) &ip_header->SrcAddr, 32);
        // payload length in network order
        sum += (payload_len & 0xFF000000) >> 8;
        sum += (payload_len & 0x00FF0000) << 8;
        sum += (payload_len & 0x0000FF00) >> 8;
        sum += (payload_len & 0x000000FF) << 8;
        sum = (sum & 0xFFFF) + (sum >> 16);
        // zero byte + protocol in network order
        sum += protocol<<8;

        // TCP
        if (protocol == 6 && len >= ip_header_len + 20 /* TCP Header */) {
            PTCP_HEADER tcp_header = (PTCP_HEADER) ((UINT8*)data + ip_header_len);

            tcp_header->Checksum = 0;
            sum += checksum_add((void*) tcp_header, len - ip_header_len);
            tcp_header->Checksum = checksum_finish(sum);

            // UDP
        } else if (protocol == 17 && len >= ip_header_len + 8 /* UDP Header */) {
            PUDP_HEADER udp_header = (PUDP_HEADER) ((UINT8*)data + ip_header_len);

            udp_header->Checksum = 0;
            sum += checksum_add((void*) udp_header, len - ip_header_len);
            udp_header->Checksum = checksum_finish(sum);

            // special case for UDP
            if (udp_header->Checksum == 0) {
                udp_header->Checksum = 0xFFFF;
            }

        }
    }
}

ULONG calc_ipv4_header_size(void* data, size_t len) {

    // sanity check
    if (!data || len == 0) {
        ERR("Invalid parameters");
        return 0;
    }

    if (len >= 20) {
        // calc IPv4 Header length
        PIPV4_HEADER ip_header = (PIPV4_HEADER) data;
        size_t ip_header_len = ip_header->HdrLength * 4;
        if (len < ip_header_len) {
            WARN("Invalid Packet len=%u, ip_header_len=%u, ip_header->HdrLength=0x%X", len, ip_header_len, ip_header->HdrLength);
            return 0;
        }
        return ip_header_len;
    }
    WARN("Invalid Packet len=%u < 20", len);
    return 0;
}

ULONG calc_ipv6_header_size(void* data, size_t len, UINT8* return_protocol) {

    // sanity check
    if (!data || len == 0) {
        ERR("Invalid parameters");
        return 0;
    }

    if (len >= 40) {
        PIPV6_HEADER ip_header = (PIPV6_HEADER) data;
        int ip_header_len = 40;
        UINT8* data8 = (UINT8*) data;
        UINT8 protocol;

        if (len < ip_header_len) {
            return 0;
        }
        protocol = ip_header->NextHdr;

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
                    if (len < ip_header_len+8) {
                        return 0;
                    }
                    protocol = data8[ip_header_len];
                    ip_header_len += 8 + data8[ip_header_len+1]*8;
                    if (len < ip_header_len) {
                        return 0;
                    }
                    break;
                default:
                    if (return_protocol != NULL) {
                        *return_protocol = protocol;
                    }
                    return ip_header_len;
            }
        }
    }
    return 0;
}
