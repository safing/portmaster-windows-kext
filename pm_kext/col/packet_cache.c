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

/**
 * @brief Retrieves the packet index located in the array
 *
 * @par    packetCache = packet cache to use
 * @par    packetID    = registered packet ID
 * @return packet index
 *
 */
static UINT32 getIndexFromPacketID(PacketCache *packetCache, UINT32 packetID) {
    return (packetID - 1) % packetCache->maxSize; // -1 because packet id starts from 1
}

/**
 * @brief Initializes the packet cache
 *
 * @par    maxSize     = size of cache
 * @par    packetCache = returns new PacketCache
 * @return error code
 *
 */
int createPacketCache(uint32_t maxSize, PacketCache **packetCache) {
    if (maxSize == 0) {
        ERR("PacketCache maxSize was 0");
        return 1;
    }
    INFO("createPacketCache with size %d", maxSize);

    PacketCache *newPacketCache = _ALLOC(sizeof(PacketCache), 1);
    if (newPacketCache == NULL) {
        return 1;
    }

    newPacketCache->packets = _ALLOC(sizeof(PacketCacheItem), maxSize);
    if(newPacketCache->packets == NULL) {
        _FREE(newPacketCache);
        return 1;
    }

    newPacketCache->nextPacketID = 1;
    newPacketCache->maxSize = maxSize;

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
int teardownPacketCache(PacketCache *packetCache, void(*freeData)(PortmasterPacketInfo*, void*)) {
    if(packetCache == NULL) {
        return 0;
    }

    for(UINT32 i = 0; i < packetCache->maxSize; i++) {
        PacketCacheItem *item = &packetCache->packets[i];
        if(item->packetInfo != NULL && item->packet != NULL) {
            freeData(item->packetInfo, item->packet);
        }
    }
    
    _FREE(packetCache->packets);
    _FREE(packetCache);
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
uint32_t registerPacket(PacketCache* packetCache, PortmasterPacketInfo *packetInfo, void* packet, size_t packetLength, PortmasterPacketInfo **oldPacketInfo, void **oldPacket) {
    DEBUG("registerPacket called");
    if(packetCache == NULL || packetInfo == NULL || packet == NULL) {
        ERR("registerPacket - invalid params");
        return 0;
    }

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
int retrievePacket(PacketCache *packetCache, UINT32 packetID, PortmasterPacketInfo **packetInfo, void **packet, size_t *packetLength) {
    DEBUG("retrieve_packet called");
    
    PacketCacheItem *item = getPacketFromID(packetCache, packetID);
    if(item == NULL) {
        return 1;
    }

    *packetInfo = item->packetInfo;
    *packet = item->packet;
    *packetLength = item->packetLength;
    memset(item, 0, sizeof(PacketCacheItem));
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
int getPacket(PacketCache *packetCache, uint32_t packetID, void **packet, size_t *packetLength) {
    DEBUG("getPacket called");

    PacketCacheItem *item = getPacketFromID(packetCache, packetID);
    if(item == NULL) {
        return 1;
    }

    *packet = item->packet;
    *packetLength = item->packetLength;
    return 0;
}
