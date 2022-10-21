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
 * @brief Initializes the packet cache
 *
 * @par    maxSize     = size of cache
 * @par    packetCache = returns new PacketCache
 * @return error code
 *
 */
int createPacketCache(uint32_t maxSize, PacketCache **packetCache) {
    if (!maxSize) {
        ERR("createPacketCache");
        return 1;
    }
    INFO("createPacketCache with size %d", maxSize);

    PacketCache *new = _ALLOC(sizeof(PacketCache), 1);
    if (!new) {
        return 1;
    }

    new->size = 0;
    new->maxSize = maxSize;
    new->nextPacketID = 1;
    *packetCache = new;

    return 0;
}

/**
 * @brief Cleans the packet cache
 *
 * @par    packetCache = packet_cache to use
 * @par    packetInfo  = returns PORTMASTER_PACKET_INFO to free
 * @par    packet       = returns void to free
 * @return error code
 *
 */
int cleanPacketCache(PacketCache *packetCache, PortmasterPacketInfo **packetInfo, void **packet) {
    if(!packetCache) {
        ERR("cleanPacketCache - invalid params");
        return 1;
    }

    if (packetCache->size <= packetCache->maxSize) { // '<=' is correct ,-)
        INFO("cleanPacketCache - current size= %d, max_size=%d -> nothing to free", packetCache->size, packetCache->maxSize);
        return 1;
    }
    
    INFO("cleanPacketCache - current size= %d, max_size=%d -> trying to drop last packet",  packetCache->size, packetCache->maxSize);

    if (packetCache->tail) {
        // get last item
        PacketCacheItem* lastItem = packetCache->tail;

        INFO("cleanPacketCache - tail exists (size=%d)-> trying to free one packet", packetCache->size);
        // remove from list
        if (lastItem->prev) {
            // reconnect tail if there is an item left
            packetCache->tail = lastItem->prev;
            // delete next of new last item
            lastItem->prev->next = NULL;
        } else {
            // reset tail (list is empty!)
            packetCache->tail = NULL;
        }

        // set return value
        *packetInfo = lastItem->packetInfo;
        *packet = lastItem->packet;

        // free
        _FREE(lastItem);
        packetCache->size--;  // Decrement size, otherwise cache will become useless eventually 
                               // so that every packet will be dropped
        INFO("cleanPacketCache - item freed, size=%d", packetCache->size);

        return 0;
    }

    return 1;
}

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
int teardownPacketCache(PacketCache *packetCache) {
    if(packetCache == NULL) {
        return 0;
    }
    
    PacketCacheItem *item = packetCache->head;
    while (item != NULL) {
        PacketCacheItem *current = item;
        item = item->next;
        _FREE(current->packetInfo);
        _FREE(current);
    }

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
uint32_t registerPacket(PacketCache* packetCache, PortmasterPacketInfo *packetInfo, void* packet, size_t packetLength) {
    DEBUG("registerPacket called");
    if(!packetCache || !packetInfo || !packet) {
        ERR("registerPacket - invalid params");
        return 0;
    }

    PacketCacheItem *newItem = _ALLOC(sizeof(PacketCacheItem), 1);
    if(!newItem) {
        ERR("registerPacket - could not allocate newItem");
        return 0;
    }

    newItem->packetID = packetCache->nextPacketID++;
    // check for overflow
    if (packetCache->nextPacketID >= ULONG_MAX) {
        packetCache->nextPacketID = 1;
    }

    newItem->packetInfo = packetInfo;
    newItem->packet = packet;
    newItem->packetLength = packetLength;

    // insert as first item
    if (packetCache->head) {
        newItem->next = packetCache->head;
        packetCache->head->prev = newItem;
    }
    packetCache->head = newItem;

    // set tail if only item
    if (!packetCache->tail) {
        packetCache->tail = newItem;
    }

    packetCache->size++;
    return newItem->packetID;
}

/**
 * @brief Retrieves a packet, if it exists. The returned packet and packet_info will be removed from the list.
 *
 * @par    packetCache = packet cache to use
 * @par    packetID    = registered packet ID
 * @par    packetInfo  = double pointer for packet_info return
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
int retrievePacket(PacketCache *packetCache, uint32_t packetID, PortmasterPacketInfo **packetInfo, void **packet, size_t *packetLength) {
    PacketCacheItem *item = packetCache->head;
    DEBUG("retrieve_packet called");
    while (item) {
        if (packetID == item->packetID) {
        
            *packetInfo = item->packetInfo;
            *packet = item->packet;
            *packetLength = item->packetLength;

            // delete item
            if (item->prev) {
                item->prev->next = item->next;
            } else {
                packetCache->head = item->next;
            }
            if (item->next) {
                item->next->prev = item->prev;
            } else {
                packetCache->tail = item->prev;
            }

            // clean
            _FREE(item);
            packetCache->size--;

            return 0;
        }
        item = item->next;
    }
    return 1;
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
    PacketCacheItem *item = packetCache->head;
    while (item) {
        if (packetID == item->packetID) {
            // set return values
            *packet = item->packet;
            *packetLength = item->packetLength;

            return 0;
        }
        item = item->next;
    }
    return 1;
}
