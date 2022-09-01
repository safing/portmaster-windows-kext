/*
 *  Name:        verdict_cache.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declaration of verdict cache.
 *               Verdicts are set by Portmaster Userland Application
 *               and cached in kernel for faster access (nona).
 *               Cache Algorithm: Least Recently Used (LRU).
 *
 *  Scope:       Kernelmode
 *               (Userland for development)
 */

#ifndef VERDICT_CACHE_H
#define VERDICT_CACHE_H

#include "pm_common.h"


typedef struct VerdictCacheItem {
    struct VerdictCacheItem *prev;
    struct VerdictCacheItem *next;

    PortmasterPacketInfo *packetInfo;
    verdict_t verdict;
} VerdictCacheItem;

typedef struct {
    UINT32 size;
    UINT32 maxSize;
    VerdictCacheItem *head;
    VerdictCacheItem *tail;
} VerdictCache;

/**
 * @brief Initializes the verdict cache
 *
 * @par    max_size      = size of cache
 * @par    verdict_cache = returns new verdictCache
 * @return error code
 *
 */
int createVerdictCache(UINT32 maxSize, VerdictCache **verdict_cache);

/**
 * @brief Cleans the verdict cache
 *
 * @par    verdictCache = verdict_cache to use
 * @par    packetInfo   = returns portmasterPacketInfo to free
 * @return error code
 *
 */
int cleanVerdictCache(VerdictCache *verdictCache, PortmasterPacketInfo **packetInfo);

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
int teardownVerdictCache(VerdictCache *verdictCache);

/**
 * @brief Adds verdict to cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
int addVerdict(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, verdict_t verdict);

/**
 * @brief Checks packet for verdict
 *
 * @par    verdictCache = verdict cache to use
 * @par    packetInfo   = pointer to packet info
 * @return verdict
 *
 */
verdict_t checkVerdict(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo);

/**
 * @brief Checks packet for reverse redirection
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @par    redir_info   = double pointer to packet_info (return value)
 * @par    verdict       = pointer to verdict (return value)
 * @return error code
 *
 */
verdict_t checkReverseRedirect(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, PortmasterPacketInfo **redirInfo);

#endif

#if 0
#ifndef DYN_ALLOC_FREE
#define DYN_ALLOC_FREE

#ifdef BUILD_ENV_DRIVER


#else

#define _ALLOC(element_size, n_of_elements) calloc(element_size, n_of_elements)
#define _FREE(p_element) free(p_element)

#endif // DYN_ALLOC_FREE
#endif // 0

#endif // VERDICT_CACHE_H
