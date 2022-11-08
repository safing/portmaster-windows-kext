/*
 *  Name:        packet_cache.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declaration of packet cache.  IP-Packets must be cached
 *               until we know what to do with them (block, drop, reinject).
 *               Caching Algorithm: Last In First Out (LIFO)
 *
 *  Scope:       Kernelmode
 *               (Userland for development)
 */

#ifndef __COL_PACKETS_H__
#define __COL_PACKETS_H__

#ifndef __LINUX_ENV__
#include <intsafe.h>
#define uint8_t  UINT8
#define uint16_t UINT16
#define uint32_t UINT32
#define uint64_t UINT64
#endif

#define PacketCache void

/**
 * @brief Initializes the packet cache
 *
 * @par    maxSize     = size of cache
 * @par    packetCache = returns new packet_cache_t
 * @return error code
 *
 */
int packetCacheCreate(uint32_t maxSize, PacketCache **packetCache);

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
int packetCacheTeardown(PacketCache *packetCache, void(*freeData)(PortmasterPacketInfo*, void*));

/**
 * @brief Registers a packet
 *
 * @par    packetCache = packetCache to use
 * @par    packetInfo  = pointer to packetInfo
 * @par    packet      = pointer to packet
 * @return new packet ID
 *
 */
uint32_t packetCacheRegister(PacketCache *packetCache, PortmasterPacketInfo *packetInfo, void *packet, size_t packetLength, PortmasterPacketInfo **oldPacketInfo, void **oldPacket);

/**
 * @brief Retrieves and deletes a packet from list, if it exists.
 *
 * @par    packetCache  = packetCache to use
 * @par    packetID     = registered packet ID
 * @par    packetCache  = double pointer for packetInfo return
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
int packetCacheRetrieve(PacketCache *packetCache, uint32_t packetID, PortmasterPacketInfo **packetInfoPtr, void **packet, size_t *packetLength);

/**
 * @brief Retrieves a packet from list, if it exists.
 *
 * @par    packetCache = packetCache to use
 * @par    packetID    = registered packet ID
 * @par    packet      = double pointer for packet return
 * @return error code
 *
 */
int packetCacheGet(PacketCache *packetCache, uint32_t packetID, void **packet, size_t *packetLength);

#endif
