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
#include "pm_debug.h"

// https://troydhanson.github.io/uthash/userguide.html
#define uthash_malloc(sz) portmasterMalloc(sz, false)
#define uthash_free(ptr, sz) portmasterFree(ptr)
#define uthash_fatal
#define HASH_NO_STDINT 1
#include "uthash.h"


typedef struct {
    UINT32 localIP[4];
    UINT16 localPort;
    UINT32 remoteIP[4];
    UINT16 remotePort;
    UINT8 protocol;
} VerdictCacheKey;

typedef struct VerdictCacheItem {
    UINT64 lastAccessed; 
    VerdictCacheKey key;
    VerdictCacheKey redirectKey;

    PortmasterPacketInfo *packetInfo;
    verdict_t verdict;

    UT_hash_handle hh;
    UT_hash_handle hhRedirect;
} VerdictCacheItem;

#undef VerdictCache // previously defined as void
typedef struct {
    VerdictCacheItem *map;
    VerdictCacheItem *mapRedirect;

    VerdictCacheItem *itemPool;
    UINT32 maxSize;
    UINT32 *freeItemIndexes;
    UINT32 numberOfFreeItems;

    KSPIN_LOCK lock;
} VerdictCache;

// Holds the number of accesses/modifications performed on the cache
static UINT64 cacheAccessCounter = 0;

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
int verdictCacheCreate(UINT32 maxSize, void **verdictCache) {
    if (maxSize == 0) {
        return 1;
    }

    VerdictCache *newVerdictCache = portmasterMalloc(sizeof(VerdictCache), false);
    if (newVerdictCache == NULL) {
        return 1;
    }

    newVerdictCache->itemPool = portmasterMalloc(sizeof(VerdictCacheItem) * maxSize, false);
    if(newVerdictCache->itemPool == NULL) {
        portmasterFree(newVerdictCache);
        return 1;
    }

    newVerdictCache->numberOfFreeItems = maxSize;

    newVerdictCache->map = NULL;
    newVerdictCache->mapRedirect = NULL;
    newVerdictCache->maxSize = maxSize;

    KeInitializeSpinLock(&newVerdictCache->lock);
    *verdictCache = newVerdictCache;

    return 0;
}

/**
 * @brief Remove all items from verdict cache
 *
 * @par    verdictCache = verdict_cache to use
 * @par    freeData = callback function that is executed for each item before delete were the data of the item can be deleted
 *
 */

void verdictCacheClear(VerdictCache *verdictCache, void(*freeData)(PortmasterPacketInfo*, verdict_t)) {
    DEBUG("verdictCacheClear");

    // Lock to check verdict cache.
    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&verdictCache->lock, &lockHandle);

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
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
int verdictCacheTeardown(VerdictCache *verdictCache, void(*freeData)(PortmasterPacketInfo*, verdict_t)) {
    if(verdictCache == NULL) {
        return 0;
    }

    verdictCacheClear(verdictCache, freeData);
    portmasterFree(verdictCache->itemPool);
    portmasterFree(verdictCache);
    return 0;
}

static VerdictCacheItem *getOldestAccessTimeItem(VerdictCache *verdictCache) {
    UINT64 oldestAccessNumber = cacheAccessCounter + 1;
    VerdictCacheItem *oldestItem = NULL;
    for(UINT32 i = 0; i < verdictCache->maxSize; i++) {
        VerdictCacheItem *current = &verdictCache->itemPool[i];
        if(current->lastAccessed < oldestAccessNumber) {
            oldestAccessNumber = current->lastAccessed;
            oldestItem = current;
        }
    }
    return oldestItem;
}

static void resetItem(VerdictCache *verdictCache, VerdictCacheItem *item) {
    HASH_DELETE(hh, verdictCache->map, item);
    // Delete redirect only if the item is in the map
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
int verdictCacheAdd(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, verdict_t verdict, PortmasterPacketInfo **removedPacketInfo) {
    if (verdictCache == NULL || packetInfo == NULL || verdict == 0) {
        ERR("verdictCacheAdd NULL pointer exception verdictCache=0p%Xp, packetInfo=0p%Xp, verdict=0p%Xp ", verdictCache, packetInfo, verdict);
        return 1;
    }

    cacheAccessCounter++;

    VerdictCacheItem *newItem = NULL;
    VerdictCacheKey key = getCacheKey(packetInfo);

    // Lock to check verdict cache.
    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&verdictCache->lock, &lockHandle);

    int rc = 0;

    #pragma warning(suppress : 4127) //  warning C4127: conditional expression is constant -> if generated by macro
    HASH_FIND(hh, verdictCache->map, &key, sizeof(VerdictCacheKey), newItem);
    if(newItem != NULL) {
        // already in
        INFO("addVerdict packet was already in the verdict cache");
        rc = 3;
    }

    if(rc == 0) {
        if(verdictCache->numberOfFreeItems > 0) {
            newItem = &verdictCache->itemPool[verdictCache->maxSize - verdictCache->numberOfFreeItems];
            verdictCache->numberOfFreeItems -= 1;
        } else {
            VerdictCacheItem *item = getOldestAccessTimeItem(verdictCache);
            if(item == NULL) {
                ERR("addVerdict failed to find free element");
                rc = 2;
            } else {
                *removedPacketInfo = item->packetInfo;
                resetItem(verdictCache, item);
                newItem = item;
            }
        }
    }

    if(rc == 0) {
        // Set key
        newItem->key = key;
        newItem->packetInfo = packetInfo;
        newItem->verdict = verdict;
        newItem->lastAccessed = cacheAccessCounter;
        HASH_ADD(hh, verdictCache->map, key, sizeof(VerdictCacheKey), newItem);

        if(verdict == PORTMASTER_VERDICT_REDIR_DNS || verdict == PORTMASTER_VERDICT_REDIR_TUNNEL) {
            newItem->redirectKey = getCacheRedirectKey(packetInfo);
            // insert only if we dont have already item with the same key
            VerdictCacheItem *redirectItem = NULL;
            #pragma warning(suppress : 4127) //  warning C4127: conditional expression is constant -> if generated by macro
            HASH_FIND(hhRedirect, verdictCache->mapRedirect, &newItem->redirectKey, sizeof(VerdictCacheKey), redirectItem);
            if(redirectItem == NULL) {
                HASH_ADD(hhRedirect, verdictCache->mapRedirect, redirectKey, sizeof(VerdictCacheKey), newItem);
            }
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return rc;
}

/**
 * @brief Checks packet for verdict
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet info
 * @return verdict
 *
 */
static verdict_t checkVerdict(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo) {
    if (verdictCache == NULL || packetInfo == NULL) {
        ERR("verdictCache 0p%xp or packet_info 0p%xp was null", verdictCache, packetInfo);
        return PORTMASTER_VERDICT_ERROR;
    }
    cacheAccessCounter++;

    if(verdictCache->map == NULL) {
        // no entries
        return PORTMASTER_VERDICT_GET;
    }

    VerdictCacheItem *item = NULL;
    VerdictCacheKey key = getCacheKey(packetInfo);
    #pragma warning(suppress : 4127) //  warning C4127: conditional expression is constant -> if generated by macro
    HASH_FIND(hh, verdictCache->map, &key, sizeof(VerdictCacheKey), item);

    if(item == NULL) {
        return PORTMASTER_VERDICT_GET;
    }

    item->lastAccessed = cacheAccessCounter;
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
static verdict_t checkReverseRedirect(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, PortmasterPacketInfo **redirInfo) {
    if (verdictCache == NULL || packetInfo == NULL || redirInfo == NULL) {
        return PORTMASTER_VERDICT_GET;
    }

    cacheAccessCounter++;

    if(verdictCache->mapRedirect == NULL) {
        // no entries
        return PORTMASTER_VERDICT_GET;
    }

    VerdictCacheItem *item = NULL;
    VerdictCacheKey key = getCacheRedirectKey(packetInfo);
    #pragma warning(suppress : 4127) //  warning C4127: conditional expression is constant -> if generated by macro
    HASH_FIND(hhRedirect, verdictCache->mapRedirect, &key, sizeof(VerdictCacheKey), item);
    if(item == NULL) {
        return PORTMASTER_VERDICT_GET;
    }
    
    item->lastAccessed = cacheAccessCounter;
    *redirInfo = item->packetInfo;
    return item->verdict;
}

verdict_t verdictCacheGet(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, PortmasterPacketInfo **redirInfo) {
    verdict_t verdict = PORTMASTER_VERDICT_GET;

    // Lock to check verdict cache.
    KLOCK_QUEUE_HANDLE lockHandle = {0};
    KeAcquireInStackQueuedSpinLock(&verdictCache->lock, &lockHandle);

    if (packetInfo->direction == DIRECTION_INBOUND &&
        (packetInfo->remotePort == PORT_PM_SPN_ENTRY || packetInfo->remotePort == PORT_DNS)) {
        verdict = checkReverseRedirect(verdictCache, packetInfo, redirInfo);

        // Verdicts returned by check_reverse_redir must only be
        // PORTMASTER_VERDICT_REDIR_DNS or PORTMASTER_VERDICT_REDIR_TUNNEL.
        if (verdict != PORTMASTER_VERDICT_REDIR_DNS && verdict != PORTMASTER_VERDICT_REDIR_TUNNEL) {
            verdict = PORTMASTER_VERDICT_GET;
        }
    }

    // Check verdict normally if we did not detect a packet that should be reverse DNAT-ed.
    if (verdict == PORTMASTER_VERDICT_GET) {
        verdict = checkVerdict(verdictCache, packetInfo);

        // If packet should be DNAT-ed set redirInfo to packetInfo.
        if (verdict == PORTMASTER_VERDICT_REDIR_DNS || verdict == PORTMASTER_VERDICT_REDIR_TUNNEL) {
            *redirInfo = packetInfo;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return verdict;
}
