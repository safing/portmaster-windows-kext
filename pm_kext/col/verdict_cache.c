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

/**
 * @brief Initializes the verdict cache
 *
 * @par    maxSize      = size of cache
 * @par    verdict_cache = returns new VerdictCache
 * @return error code
 *
 */
int createVerdictCache(UINT32 maxSize, VerdictCache **verdictCache) {
    VerdictCache* newVerdictCache;

    if (!maxSize) {
        return 1;
    }
    newVerdictCache = _ALLOC(sizeof(VerdictCache), 1);
    if (!newVerdictCache) {
        return 1;
    }

    newVerdictCache->size = 0;
    newVerdictCache->maxSize = maxSize;
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

    if (verdictCache->size <= verdictCache->maxSize) {
        return 1;
    }

    if (verdictCache->tail) {
        // get last item
        VerdictCacheItem *lastItem = verdictCache->tail;

        // remove from list
        if (lastItem->prev) {
            // reconnect tail if there is an item left
            verdictCache->tail = lastItem->prev;
            // delete next of new last item
            lastItem->prev->next = NULL;
        } else {
            // reset tail (list is empty!)
            verdictCache->tail = NULL;
        }

        // set return value
        *packetInfo = lastItem->packetInfo;

        // free
        _FREE(lastItem);
        verdictCache->size--;

        return 0;
    }

    return 1;
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

    VerdictCacheItem *newItem = _ALLOC(sizeof(VerdictCacheItem), 1);
    if(!newItem) {
        ERR("add_verdict tried to add NULL-Pointer verdict");
        return 2;
    }

    newItem->packetInfo = packetInfo;
    newItem->verdict = verdict;

    // insert as first item
    if (verdictCache->head) {
        newItem->next = verdictCache->head;
        verdictCache->head->prev = newItem;
    }
    verdictCache->head = newItem;

    // set tail if only item
    if (!verdictCache->tail) {
        verdictCache->tail = newItem;
    }

    verdictCache->size++;
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

    // check if list is empty
    if (!verdictCache->head) {
        INFO("verdictCache was empty");
        return PORTMASTER_VERDICT_GET;
    }

    // check first item
    if (compareFullPacketInfo(packetInfo, verdictCache->head->packetInfo)) {
        DEBUG("compareFullPacketInfo successful");
        return verdictCache->head->verdict;
    }

    // check the rest of the list
    VerdictCacheItem *item = verdictCache->head->next;
    while (item) {
        if (compareFullPacketInfo(packetInfo, item->packetInfo)) {
            // pull item to front
            if (item->next) {
                // connect previous and next items
                item->prev->next = item->next;
                item->next->prev = item->prev;
            } else {
                // connect new last item with list tail
                item->prev->next = NULL;
                verdictCache->tail = item->prev;
            }
            // insert in front
            item->prev = NULL;
            item->next = verdictCache->head;
            verdictCache->head->prev = item;
            verdictCache->head = item;

            // success
            return item->verdict;
        }
        item = item->next;
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

    // check if list is empty
    if (!verdictCache->head) {
        return PORTMASTER_VERDICT_GET;
    }

    // check first item
    if (compareReverseRedirPacketInfo(verdictCache->head->packetInfo, packetInfo)) {
        *redirInfo = verdictCache->head->packetInfo;
        return verdictCache->head->verdict;
    }

    // check the rest of the list
    VerdictCacheItem *item = verdictCache->head->next;
    while (item) {
        if (compareReverseRedirPacketInfo(item->packetInfo, packetInfo)) {

            // pull item to front
            if (item->next) {
                // connect previous and next items
                item->prev->next = item->next;
                item->next->prev = item->prev;
            } else {
                // connect new last item with list tail
                item->prev->next = NULL;
                verdictCache->tail = item->prev;
            }
            // insert in front
            item->prev = NULL;
            item->next = verdictCache->head;
            verdictCache->head->prev = item;
            verdictCache->head = item;

            // set return value
            *redirInfo = item->packetInfo;
            return item->verdict;
        }
        item = item->next;
    }

    return PORTMASTER_VERDICT_GET;
}
