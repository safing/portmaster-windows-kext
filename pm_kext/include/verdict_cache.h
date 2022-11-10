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
#include "pm_utils.h"

#ifndef __LINUX_ENV__
#include <intsafe.h>
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#endif

#define VerdictCache void

/**
 * @brief Initializes the verdict cache
 *
 * @par    max_size      = size of cache
 * @par    verdict_cache = returns new verdictCache
 * @return error code
 *
 */
int verdictCacheCreate(UINT32 maxSize, VerdictCache **verdict_cache);

/**
 * @brief Remove all items from verdict cache
 *
 * @par    verdict_cache = VerdictCache to use
 * @par    freeData = callback function that is executed for each item before delete were the data of the item can be deleted
 *
 */
void verdictCacheClear(VerdictCache *verdictCache, void(*freeData)(PortmasterPacketInfo*, verdict_t));

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdictCache = verdict cache to use
 * @return error code
 *
 */
int verdictCacheTeardown(VerdictCache *verdictCache, void(*freeData)(PortmasterPacketInfo*, verdict_t));

/**
 * @brief Updates a verdict that is already in the cache
 *
 * @par    verdict_cache = VerdictCache to use
 * @par    info   = pointer to verdictUpdateInfo
 * @return error code
 *
 */
int verdictCacheUpdate(VerdictCache *verdictCache, VerdictUpdateInfo *info);

/**
 * @brief Adds verdict to cache
 *
 * @par    verdictCache = VerdictCache to use
 * @par    packetInfo   = pointer to PacketInfo
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
int verdictCacheAdd(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, verdict_t verdict, PortmasterPacketInfo **removedPacketInfo);


/**
 * @brief returns the verdict of a packet if inside the cache, with redirect info if available
 *
 * @par    verdictCache = VerdictCache to use
 * @par    packetInfo   = pointer to PacketInfo
 * @par    redirInfo    = double pointer to packetInfo (return value)
 * @par    verdict       = pointer to verdict (return value)
 * @return error code
 *
 */
verdict_t verdictCacheGet(VerdictCache *verdictCache, PortmasterPacketInfo *packetInfo, PortmasterPacketInfo **redirInfo);
#endif // VERDICT_CACHE_H
