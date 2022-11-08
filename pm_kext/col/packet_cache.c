/*
 *  Name:        packet_cache.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of packet cache.  IP-Packets must be cached
 *               until we know what to do with them (block, drop, reinject).
 *               Caching Algorithm: Last In First Out (LIFO)
 *
 *  Scope:       Kernelmode
 *               (Userland for development)
 */

#define BUILD_ENV_DRIVER

#include <stdlib.h>
#include <limits.h>

#include "pm_kernel.h"
#include "pm_common.h"
#include "packet_cache.h"
#include "pm_utils.h"
#include "pm_debug.h"

typedef struct PacketCacheItem {
    UINT32 packetID;
    PortmasterPacketInfo *packetInfo;
    void *packet;
    size_t packetLength;
} PacketCacheItem;

#undef PacketCache // previously defined as void
typedef struct  {
    PacketCacheItem *packets;
    UINT32 maxSize;
    UINT32 nextPacketID;
    KSPIN_LOCK lock;
} PacketCache;

/**
 * @brief Retrieves the packet index located in the array
 *
 * @par    packetCache = packet cache to use
 * @par    packetID    = registered packet ID
 * @return packet index
 *
 */
static UINT32 getIndexFromPacketID(PacketCache *packetCache, UINT32 packetID) {
    return packetID % packetCache->maxSize;
}

/**
 * @brief Initializes the packet cache
 *
 * @par    maxSize     = size of cache
 * @par    packetCache = returns new PacketCache
 * @return error code
 *
 */
int packetCacheCreate(uint32_t maxSize, PacketCache **packetCache) {
    if (maxSize == 0) {
        ERR("packetCacheCreate PacketCache maxSize was 0");
        return 1;
    }
    INFO("packetCacheCreate with size %d", maxSize);

    PacketCache *newPacketCache = portmasterMalloc(sizeof(PacketCache), false);
    if (newPacketCache == NULL) {
        return 1;
    }

    newPacketCache->packets = portmasterMalloc(sizeof(PacketCacheItem) * maxSize, false);
    if(newPacketCache->packets == NULL) {
        portmasterFree(newPacketCache);
        return 1;
    }

    newPacketCache->nextPacketID = 1;
    newPacketCache->maxSize = maxSize;

    KeInitializeSpinLock(&newPacketCache->lock);

    *packetCache = newPacketCache;
    return 0;
}

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
int packetCacheTeardown(PacketCache *packetCache, void(*freeData)(PortmasterPacketInfo*, void*)) {
    if(packetCache == NULL) {
        return 0;
    }

    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&packetCache->lock, &lockHandle);

    for(UINT32 i = 0; i < packetCache->maxSize; i++) {
        PacketCacheItem *item = &packetCache->packets[i];
        if(item->packetInfo != NULL && item->packet != NULL) {
            freeData(item->packetInfo, item->packet);
        }
    }
    
    portmasterFree(packetCache->packets);
    portmasterFree(packetCache);

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return 0;
}

/**
 * @brief Registers a packet
 *
 * @par    packetCache = packet cache to use
 * @par    packetInfo  = pointer to packetInfo
 * @par    packet       = pointer to packet
 * @return new packet ID
 *
 */
uint32_t packetCacheRegister(PacketCache* packetCache, PortmasterPacketInfo *packetInfo, void* packet, size_t packetLength, PortmasterPacketInfo **oldPacketInfo, void **oldPacket) {
    DEBUG("packetCacheRegister called");
    if(packetCache == NULL || packetInfo == NULL || packet == NULL) {
        ERR("packetCacheRegister - invalid params");
        return 0;
    }

    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&packetCache->lock, &lockHandle);

    UINT32 packetIndex = getIndexFromPacketID(packetCache, packetCache->nextPacketID);
    PacketCacheItem *newItem = &packetCache->packets[packetIndex];

    if(newItem->packetInfo != NULL && newItem->packet != NULL) {
        *oldPacketInfo = newItem->packetInfo;
        *oldPacket = newItem->packet;
        memset(newItem, 0, sizeof(PacketCacheItem));
    }

    newItem->packetID = packetCache->nextPacketID;
    newItem->packetInfo = packetInfo;
    newItem->packet = packet;
    newItem->packetLength = packetLength;

    packetCache->nextPacketID++;
    // check for overflow
    if (packetCache->nextPacketID >= UINT_MAX) {
        packetCache->nextPacketID = 1;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return newItem->packetID;
}

/**
 * @brief Retrieves the packetItem located in the array
 *
 * @par    packetCache = packet cache to use
 * @par    packetID    = registered packet ID
 * @return packet item
 *
 */
static PacketCacheItem* getPacketFromID(PacketCache *packetCache, UINT32 packetID) {
    if(packetID == 0) {
        return NULL;
    }
    UINT32 index = getIndexFromPacketID(packetCache, packetID);

    PacketCacheItem *item = &packetCache->packets[index];
    if(packetID != item->packetID) {
        DEBUG("Packet ID differs: %d %d", packetID, item->packetID);
        return NULL;
    }

    return item;
}

/**
 * @brief Retrieves a packet, if it exists. The returned packet and packet_info will be removed from the list.
 *
 * @par    packetCache = packet cache to use
 * @par    packetID    = registered packet ID
 * @par    packetInfo  = double pointer for packet_info return
 * @par    packet      = double pointer for packet return
 * @return error code
 *
 */
int packetCacheRetrieve(PacketCache *packetCache, UINT32 packetID, PortmasterPacketInfo **packetInfo, void **packet, size_t *packetLength) {
    DEBUG("retrieve_packet called");

    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&packetCache->lock, &lockHandle);
    PacketCacheItem *item = getPacketFromID(packetCache, packetID);
    
    if(item != NULL) {
        *packetInfo = item->packetInfo;
        *packet = item->packet;
        *packetLength = item->packetLength;
        memset(item, 0, sizeof(PacketCacheItem));
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    if(item == NULL) {
        return 1;
    }
    return 0;
}

/**
 * @brief Returns a packet, if it exists. The list is not changed.
 *
 * @par    packetCache = packet cache to use
 * @par    packetID    = registered packet ID
 * @par    packet      = double pointer for packet return
 * @return error code
 *
 */
int packetCacheGet(PacketCache *packetCache, uint32_t packetID, void **packet, size_t *packetLength) {
    DEBUG("packetCacheGet called");

    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&packetCache->lock, &lockHandle);

    PacketCacheItem *item = getPacketFromID(packetCache, packetID);
    if(item != NULL) {
        *packet = item->packet;
        *packetLength = item->packetLength;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if(item == NULL) {
        return 1;
    }
    return 0;
}
