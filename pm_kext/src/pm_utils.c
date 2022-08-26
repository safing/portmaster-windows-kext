/*
 *  Name:        pm_utils.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utility-functions
 *
 *  Scope:       Kernelmode
 */

#include <wdm.h>
#include <windef.h>
#include "pm_common.h"
#include "pm_debug.h"
#include "pm_utils.h"

/*
 * PORTMASTER malloc/free.
 */
static POOL_TYPE nonPagedPool = NonPagedPool;

void *portmasterMalloc(size_t size, BOOL paged) {
    POOL_TYPE pool = (paged? PagedPool: nonPagedPool);
    if (size == 0) {
        return NULL;
    }
    void *pv = ExAllocatePoolWithTag(pool, size, PORTMASTER_TAG);
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

BOOL isIPv4Loopback(UINT32 addr) {
    return (addr & IPv4_LOCALHOST_NET_MASK) == IPv4_LOCALHOST_NET;
}

BOOL isIPv6Loopback(UINT32 *addr) {
    return addr[0] == 0 &&
           addr[1] == 0 &&
           addr[2] == 0 &&
           addr[3] == IPv6_LOCALHOST_PART4;
}

BOOL isPacketLoopback(PortmasterPacketInfo *packet) {
    if(packet->ipV6) {
        return isIPv6Loopback(packet->remoteIP);
    } else {
        return isIPv4Loopback(packet->remoteIP[0]);
    }
}