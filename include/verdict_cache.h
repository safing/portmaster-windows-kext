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

#ifndef __COL_VERDICTS_H__
#define __COL_VERDICTS_H__

#include "pm_common.h"


typedef struct {
    PVerdictCacheItem prev;
    PVerdictCacheItem next;

    PPortmasterPacketInfo* packetInfo;
    verdict_t verdict;
} VerdictCacheItem, *PVerdictCacheItem;

typedef struct  {
    UINT32 size;
    UINT32 max_size;
    verdict_cache_item_t* head;
    verdict_cache_item_t* tail;
} VerdictCache;

/**
 * @brief Initializes the verdict cache
 *
 * @par    max_size      = size of cache
 * @par    verdict_cache = returns new verdictCache
 * @return error code
 *
 */
extern int createVerdictCache(UINT32 maxSize, PVerdictCache *verdict_cache);

/**
 * @brief Cleans the verdict cache
 *
 * @par    verdictCache = verdict_cache to use
 * @par    packetInfo   = returns portmasterPacketInfo to free
 * @return error code
 *
 */
extern int cleanVerdictCache(PVerdictCache verdictCache, PPortmasterPacketInfo* packetInfo);

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
extern int teardownVerdictCache(VerdictCache* verdictCache);

/**
 * @brief Adds verdict to cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
extern int addVerdict(PVerdictCache verdictCache, PPortmasterPacketInfo packetInfo, verdict_t verdict);

/**
 * @brief Checks packet for verdict
 *
 * @par    verdictCache = verdict cache to use
 * @par    packetInfo   = pointer to packet info
 * @return verdict
 *
 */
extern verdict_t check_verdict(verdictCache *verdictCache, PPortmasterPacketInfo* packetInfo);

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
extern verdict_t checkReverseRedir(PVerdictCache verdictCache, PPortmasterPacketInfo packetInfo, PPortmasterPacketInfo *redirInfo);

#endif

#if 0
#ifndef DYN_ALLOC_FREE
#define DYN_ALLOC_FREE

#ifdef BUILD_ENV_DRIVER


#else

#define _ALLOC(element_size, n_of_elements) calloc(element_size, n_of_elements)
#define _FREE(p_element) free(p_element)

#endif
#endif
#endif
