/*
 *  Name:        pm_utils.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utility-functions
 *
 *  Scope:       Kernelmode
 */

#include "pm_utils.h"
#include "pm_debug.h"

/*
 * PORTMASTER malloc/free.
 */

void *portmasterMalloc(size_t size, bool paged) {
    POOL_TYPE poolFlag = (paged ? PagedPool : NonPagedPool);
    if (size == 0) {
        return NULL;
    }
    // ExAllocatePoolWithTag is deprecated but there is no working (tested) alternative for it in the old Windows versions 
    // ExAllocatePoolZero -> complies but crashes the kernel
    // ExAllocatePool2 -> available with Windows 10, version 2004 and after (release around 2020)
    #pragma warning(suppress : 4996)
    void *pv = ExAllocatePoolWithTag(poolFlag, size, PORTMASTER_TAG);
    if (pv != 0) {
        RtlZeroMemory(pv, size);
    }
    return pv;
}

void portmasterFree(void *ptr) {
    if (ptr != NULL) {
        ExFreePoolWithTag(ptr, PORTMASTER_TAG);
    }
}

bool isIPv4Loopback(UINT32 addr) {
    return (addr & IPv4_LOCALHOST_NET_MASK) == IPv4_LOCALHOST_NET;
}

bool isIPv6Loopback(UINT32 *addr) {
    return addr[0] == 0 &&
           addr[1] == 0 &&
           addr[2] == 0 &&
           addr[3] == IPv6_LOCALHOST_PART4;
}

bool isPacketLoopback(PortmasterPacketInfo *packet) {
    if(packet->ipV6) {
        return isIPv6Loopback(packet->remoteIP);
    } else {
        return isIPv4Loopback(packet->remoteIP[0]);
    }
}

/**
 * @brief Compares two PORTMASTER_PACKET_INFO for full equality
 *
 * @par    a  = PORTMASTER_PACKET_INFO to compare
 * @par    b  = PORTMASTER_PACKET_INFO to compare
 * @return equality (bool as int)
 *
 */
bool compareFullPacketInfo(PortmasterPacketInfo *a, PortmasterPacketInfo *b) {
    // IP#, Protocol
    if (a->ipV6 != b->ipV6) {
        return false;
    }
    if (a->protocol != b->protocol) {
        return false;
    }

    // Ports
    if (a->localPort != b->localPort) {
        return false;
    }
    if (a->remotePort != b->remotePort) {
        return false;
    }

    // IPs
    for (int i = 0; i < 4; i++) {
        if (a->localIP[i] != b->localIP[i]) {
            return false;
        }
        if (a->remoteIP[i] != b->remoteIP[i]) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Compares two PORTMASTER_PACKET_INFO for local adress equality
 *
 * @par    original  = original PORTMASTER_PACKET_INFO to compare
 * @par    current   = new (of current packet) PORTMASTER_PACKET_INFO to compare
 * @return equality (bool as int)
 *
 */
bool compareReverseRedirPacketInfo(PortmasterPacketInfo *original, PortmasterPacketInfo *current) {
    // IP#, Protocol
    if (original->ipV6 != current->ipV6) {
        return false;
    }
    if (original->protocol != current->protocol) {
        return false;
    }

    // Ports
    if (original->localPort != current->localPort) {
        return false;
    }

    // IPs
    for (int i = 0; i < 4; i++) {
        if (original->localIP[i] != current->localIP[i]) {
            return false;
        }
    }

    // check local original IP (that we DNAT to) against the new remote IP
    // this is always the case for returning DNATed packets
    for (int i = 0; i < 4; i++) {
        if (original->localIP[i] != current->remoteIP[i]) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Compares two PORTMASTER_PACKET_INFO for remote address equality
 *
 * @par    a  = PORTMASTER_PACKET_INFO to compare
 * @par    b  = PORTMASTER_PACKET_INFO to compare
 * @return equality (bool as int)
 *
 */
int compareRemotePacketInfo(PortmasterPacketInfo *a, PortmasterPacketInfo *b) {
    // IP#, Protocol
    if (a->ipV6 != b->ipV6) {
        return false;
    }
    if (a->protocol != b->protocol) {
        return false;
    }

    // Ports
    if (a->remotePort != b->remotePort) {
        return false;
    }

    // IPs
    for (int i = 0; i < 4; i++) {
        if (a->remoteIP[i] != b->remoteIP[i]) {
            return false;
        }
    }

    return true;
}

NTSTATUS copyIPv6(const FWPS_INCOMING_VALUES* inFixedValues, FWPS_FIELDS_OUTBOUND_IPPACKET_V6 idx, UINT32* ip) {
    // sanity check
    if (!inFixedValues || !ip) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    // check type
    if (inFixedValues->incomingValue[idx].value.type != FWP_BYTE_ARRAY16_TYPE) {
        ERR("invalid IPv6 data type: 0x%X", inFixedValues->incomingValue[idx].value.type);
        ip[0] = ip[1] = ip[2] = ip[3] = 0;
        return STATUS_INVALID_PARAMETER;
    }

    // copy and swap
    UINT32* ipV6 = (UINT32*) inFixedValues->incomingValue[idx].value.byteArray16->byteArray16;
    for (int i = 0; i < 4; i++) {
        ip[i]= RtlUlongByteSwap(ipV6[i]);
    }

    return STATUS_SUCCESS;
}

size_t NetBufferDataLength(PNET_BUFFER nb) {
    return NET_BUFFER_DATA_LENGTH(nb);
}