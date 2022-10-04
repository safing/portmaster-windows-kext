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

static VerdictCacheKey getCacheKey(PortmasterPacketInfo *info) {
    VerdictCacheKey key = {0};
    memcpy(key.localIP, info->localIP, sizeof(key.localIP));
    key.localPort = info->localPort;
    memcpy(key.remoteIP, info->remoteIP, sizeof(key.remoteIP));
    key.remotePort = info->remotePort;
    return key;
}

static VerdictCacheKey getCacheRedirectKey(PortmasterPacketInfo *info) {
    VerdictCacheKey key = {0};
    memcpy(key.localIP, info->localIP, sizeof(key.localIP));
    key.localPort = info->localPort;
    memcpy(key.remoteIP, info->localIP, sizeof(key.remoteIP));
    key.remotePort = 0;
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
    if (!maxSize) {
        return 1;
    }
    VerdictCache* newVerdictCache = _ALLOC(sizeof(VerdictCache), 1);
    if (!newVerdictCache) {
        return 1;
    }

    newVerdictCache->items = NULL;
    newVerdictCache->redirect = NULL;

    *verdictCache = newVerdictCache;
    return 0;
}

/**
 * @brief Cleans the verdict cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packetInfo   = returns portmaster_packet_info to free
 * @return error code
 *
 */
int cleanVerdictCache(VerdictCache *verdictCache, PortmasterPacketInfo **packetInfo) {
    if (!verdictCache) {
        return 1;
    }

    // if (verdictCache->size <= verdictCache->maxSize) {
    //     return 1;
    // }

    // if (verdictCache->tail) {
    //     // get last item
    //     VerdictCacheItem *lastItem = verdictCache->tail;

    //     // remove from list
    //     if (lastItem->prev) {
    //         // reconnect tail if there is an item left
    //         verdictCache->tail = lastItem->prev;
    //         // delete next of new last item
    //         lastItem->prev->next = NULL;
    //     } else {
    //         // list is empty! reset it
    //         verdictCache->tail = NULL;
    //         verdictCache->head = NULL;
    //     }

    //     // set return value
    //     *packetInfo = lastItem->packetInfo;

    //     // free
    //     _FREE(lastItem);
    //     verdictCache->size--;

    //     return 0;
    // }

    return 1;
}

/**
 * @brief Remove all items from verdict cache
 *
 * @par    verdictCache = verdict_cache to use
 *
 */
void clearAllEntriesFromVerdictCache(VerdictCache *verdictCache) {
    // VerdictCacheItem *item = verdictCache->head;
    // while(item != NULL) {
    //     VerdictCacheItem *next = item->next;
    //     _FREE(item);
    //     item = next;
    // }
    // verdictCache->size = 0;
    // verdictCache->head = NULL;
    // verdictCache->tail = NULL;

    VerdictCacheItem *item = NULL;
    VerdictCacheItem *tmp = NULL;
    HASH_ITER(hh, verdictCache->items, item, tmp) {
        HASH_DEL(verdictCache->items, item);  /* delete; users advances to next */
        _FREE(item->packetInfo);
        _FREE(item);             /* optional- if you want to free  */
    }

    item = NULL;
    tmp = NULL;
    HASH_ITER(hhRedirect, verdictCache->redirect, item, tmp) {
        HASH_DEL(verdictCache->redirect, item);  /* delete; users advances to next */
        _FREE(item->packetInfo);
        _FREE(item);             /* optional- if you want to free  */
    }

    verdictCache->items = NULL;
    verdictCache->redirect = NULL;
}


/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
int teardownVerdictCache(VerdictCache *verdictCache) {
    UNREFERENCED_PARAMETER(verdictCache);
    // FIXME: implement
    return 0;
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
int addVerdict(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, verdict_t verdict) {
    if (!verdictCache || !packetInfo || !verdict) {
        ERR("add_verdict NULL pointer exception verdictCache=0p%Xp, packetInfo=0p%Xp, verdict=0p%Xp ", verdictCache, packetInfo, verdict);
        return 1;
    }

    VerdictCacheItem *newItem = NULL;

    VerdictCacheKey key = getCacheKey(packetInfo);
    HASH_FIND(hh, verdictCache->items, &key, sizeof(VerdictCacheKey), newItem);
    if(newItem != NULL) {
        // already in
        return 3;
    }

    newItem = _ALLOC(sizeof(VerdictCacheItem), 1);
    if(!newItem) {
        ERR("add_verdict tried to add NULL-Pointer verdict");
        return 2;
    }

    // Set key
    newItem->key = key;
    newItem->redirectKey = getCacheRedirectKey(packetInfo);
    newItem->packetInfo = packetInfo;
    newItem->verdict = verdict;

    HASH_ADD(hh, verdictCache->items, key, sizeof(VerdictCacheKey), newItem);
    HASH_ADD(hhRedirect, verdictCache->redirect, redirectKey, sizeof(VerdictCacheKey), newItem);
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
    if (!verdictCache || !packetInfo) {
        ERR("verdictCache 0p%xp or packet_info 0p%xp was null", verdictCache, packetInfo);
        return PORTMASTER_VERDICT_ERROR;
    }

    VerdictCacheItem *item = NULL;
    VerdictCacheKey key = getCacheKey(packetInfo);
    HASH_FIND(hh, verdictCache->items, &key, sizeof(VerdictCacheKey), item);

    if(item != NULL) {
        return item->verdict;
    }

    return PORTMASTER_VERDICT_GET;
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
    if (!verdictCache || !packetInfo || !redirInfo) {
        return PORTMASTER_VERDICT_GET;
    }

    VerdictCacheItem *item = NULL;
    VerdictCacheKey key = getCacheRedirectKey(packetInfo);
    HASH_FIND(hhRedirect, verdictCache->redirect, &key, sizeof(VerdictCacheKey), item);

    if(item != NULL) {
        return item->verdict;
    }

    return PORTMASTER_VERDICT_GET;
}
