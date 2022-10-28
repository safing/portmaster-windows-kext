/*
 *  Name:        verdict_cache.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of verdict cache.
 *               Cache Algorithm: Least Recently Used (LRU).
 *
 *  Scope:       Kernelmode
 *               (Userland for development)
 */

#define BUILD_ENV_DRIVER

#include <stdlib.h>
#include <limits.h>

#include <ntdef.h>

#include "pm_kernel.h"
#include "verdict_cache.h"
#include "pm_utils.h"
#include "pm_debug.h"

static UINT64 counter = 0;

static VerdictCacheKey getCacheKey(PortmasterPacketInfo *info) {
    VerdictCacheKey key = {0};
    memcpy(key.localIP, info->localIP, sizeof(UINT32) * 4);
    key.localPort = info->localPort;
    memcpy(key.remoteIP, info->remoteIP, sizeof(UINT32) * 4);
    key.remotePort = info->remotePort;
    key.protocol = info->protocol;
    return key;
}

static VerdictCacheKey getCacheRedirectKey(PortmasterPacketInfo *info) {
    VerdictCacheKey key = {0};
    memcpy(key.localIP, info->localIP, sizeof(UINT32) * 4);
    key.localPort = info->localPort;
    memcpy(key.remoteIP, info->localIP, sizeof(UINT32) * 4);
    key.remotePort = 0;
    key.protocol = info->protocol;
    return key;
}

/**
 * @brief Initializes the verdict cache
 *
 * @par    maxSize      = size of cache
 * @par    verdict_cache = returns new VerdictCache
 * @return error code
 *
 */
int createVerdictCache(UINT32 maxSize, VerdictCache **verdictCache) {
    if (maxSize == 0) {
        return 1;
    }

    VerdictCache *newVerdictCache = _ALLOC(sizeof(VerdictCache), 1);
    if (newVerdictCache == NULL) {
        return 1;
    }

    newVerdictCache->itemPool = _ALLOC(sizeof(VerdictCacheItem), maxSize);
    if(newVerdictCache->itemPool == NULL) {
        _FREE(newVerdictCache);
        return 1;
    }

    newVerdictCache->numberOfFreeItems = maxSize;

    newVerdictCache->map = NULL;
    newVerdictCache->mapRedirect = NULL;
    newVerdictCache->maxSize = maxSize;

    *verdictCache = newVerdictCache;
    counter = 0;
    return 0;
}

/**
 * @brief Remove all items from verdict cache
 *
 * @par    verdictCache = verdict_cache to use
 * @par    freeData = callback function that is executed for each item before delete were the data of the item can be deleted
 *
 */

void clearAllEntriesFromVerdictCache(VerdictCache *verdictCache, void(*freeData)(PortmasterPacketInfo*, verdict_t)) {
    DEBUG("clearAllEntriesFromVerdictCache");
    HASH_CLEAR(hh, verdictCache->map);
    HASH_CLEAR(hhRedirect, verdictCache->mapRedirect);

    for(UINT32 i = 0; i < verdictCache->maxSize; i++) {
        VerdictCacheItem *item = &verdictCache->itemPool[i];
        if(item->packetInfo != NULL) {
            freeData(item->packetInfo, item->verdict);
        }
    }

    memset(verdictCache->itemPool, 0, sizeof(VerdictCacheItem) * verdictCache->maxSize);
    verdictCache->numberOfFreeItems = verdictCache->maxSize;
    verdictCache->map = NULL;
    verdictCache->mapRedirect = NULL;
    counter = 0;
}

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
int teardownVerdictCache(VerdictCache *verdictCache, void(*freeData)(PortmasterPacketInfo*, verdict_t)) {
    if(verdictCache == NULL) {
        return 0;
    }
    
    clearAllEntriesFromVerdictCache(verdictCache, freeData);
    _FREE(verdictCache->itemPool);
    _FREE(verdictCache);
    return 0;
}

static VerdictCacheItem *getOldestAccessTimeItem(VerdictCache *verdictCache) {
    UINT64 oldestTimestamp = counter + 1;
    VerdictCacheItem *oldestItem = NULL;
    for(UINT32 i = 0; i < verdictCache->maxSize; i++) {
        VerdictCacheItem *current = &verdictCache->itemPool[i];
        if(current->lastAccessed < oldestTimestamp) {
            oldestTimestamp = current->lastAccessed;
            oldestItem = current;
        }
    }
    return oldestItem;
}

static void resetItem(VerdictCache *verdictCache, VerdictCacheItem *item) {
    HASH_DELETE(hh, verdictCache->map, item);
    // Delete redirect only if the item is in the map
    // check if we have a key instead of calling HASH_FIND
    if(item->hhRedirect.key != NULL) { 
        HASH_DELETE(hhRedirect, verdictCache->mapRedirect, item);
    }
    memset(item, 0, sizeof(VerdictCacheItem));
}

/**
 * @brief Adds verdict to cache
 *
 * @par    verdictCache = verdict cache to use
 * @par    packet_info   = pointer to packet_info
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
int addVerdict(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, verdict_t verdict, PortmasterPacketInfo **removedPacketInfo) {
    if (verdictCache == NULL || packetInfo == NULL || verdict == 0) {
        ERR("addVerdict NULL pointer exception verdictCache=0p%Xp, packetInfo=0p%Xp, verdict=0p%Xp ", verdictCache, packetInfo, verdict);
        return 1;
    }

    counter++;

    VerdictCacheItem *newItem = NULL;

    VerdictCacheKey key = getCacheKey(packetInfo);
    HASH_FIND(hh, verdictCache->map, &key, sizeof(VerdictCacheKey), newItem);
    if(newItem != NULL) {
        INFO("addVerdict packet was already in");
        // already in
        return 3;
    }

    if(verdictCache->numberOfFreeItems > 0) {
        newItem = &verdictCache->itemPool[verdictCache->maxSize - verdictCache->numberOfFreeItems];
        verdictCache->numberOfFreeItems -= 1;
    } else {
        VerdictCacheItem *item = getOldestAccessTimeItem(verdictCache);
        if(item == NULL) {
            ERR("addVerdict failed to find free element");
            return 2;
        }
        *removedPacketInfo = item->packetInfo;
        resetItem(verdictCache, item);
        newItem = item;
    }

    // Set key
    newItem->key = key;
    newItem->redirectKey = getCacheRedirectKey(packetInfo);
    newItem->packetInfo = packetInfo;
    newItem->verdict = verdict;
    newItem->lastAccessed = counter;
    HASH_ADD(hh, verdictCache->map, key, sizeof(VerdictCacheKey), newItem);

    // insert only if we dont have already item with the same key
    VerdictCacheItem *redirectItem = NULL;
    HASH_FIND(hhRedirect, verdictCache->mapRedirect, &newItem->redirectKey, sizeof(VerdictCacheKey), redirectItem);
    if(redirectItem == NULL) {
        HASH_ADD(hhRedirect, verdictCache->mapRedirect, redirectKey, sizeof(VerdictCacheKey), newItem);
    }

    return 0;
}

/**
 * @brief Checks packet for verdict
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet info
 * @return verdict
 *
 */
verdict_t checkVerdict(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo) {
    if (verdictCache == NULL || packetInfo == NULL) {
        ERR("verdictCache 0p%xp or packet_info 0p%xp was null", verdictCache, packetInfo);
        return PORTMASTER_VERDICT_ERROR;
    }

    counter++;

    if(verdictCache->map == NULL) {
        // no entries
        return PORTMASTER_VERDICT_GET;
    }

    VerdictCacheItem *item = NULL;
    VerdictCacheKey key = getCacheKey(packetInfo);
    HASH_FIND(hh, verdictCache->map, &key, sizeof(VerdictCacheKey), item);

    if(item == NULL) {
        return PORTMASTER_VERDICT_GET;
    }

    item->lastAccessed = counter;
    return item->verdict;
}

/**
 * @brief Checks packet for reverse redirection
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packetInfo   = pointer to packet info
 * @par    redirInfo   = double pointer to packet_info (return value)
 * @par    verdict       = pointer to verdict (return value)
 * @return error code
 *
 */
verdict_t checkReverseRedirect(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, PortmasterPacketInfo **redirInfo) {
    if (verdictCache == NULL || packetInfo == NULL || redirInfo == NULL) {
        return PORTMASTER_VERDICT_GET;
    }

    counter++;

    if(verdictCache->mapRedirect == NULL) {
        // no entries
        return PORTMASTER_VERDICT_GET;
    }

    VerdictCacheItem *item = NULL;
    VerdictCacheKey key = getCacheRedirectKey(packetInfo);
    HASH_FIND(hhRedirect, verdictCache->mapRedirect, &key, sizeof(VerdictCacheKey), item);
    if(item == NULL) {
        return PORTMASTER_VERDICT_GET;
    }
    
    item->lastAccessed = counter;
    *redirInfo = item->packetInfo;
    return item->verdict;
}
