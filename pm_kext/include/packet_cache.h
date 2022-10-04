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

typedef struct PacketCacheItem {
    struct PacketCacheItem *prev;
    struct PacketCacheItem *next;

    uint32_t packetID;
    PortmasterPacketInfo *packetInfo;
    void *packet;
    size_t packetLength;
    /*
    COMPARTMENT_ID compartmentId;
    IF_INDEX interfaceIndex;
    IF_INDEX subInterfaceIndex;
    */
} PacketCacheItem;

typedef struct  {
    uint32_t size;
    uint32_t maxSize;
    uint32_t nextPacketID;
    PacketCacheItem *head;
    PacketCacheItem *tail;
} PacketCache;


extern PacketCache *globalPacketCache;
extern KSPIN_LOCK globalPacketCacheLock;


/**
 * @brief Initializes the packet cache
 *
 * @par    maxSize     = size of cache
 * @par    packetCache = returns new packet_cache_t
 * @return error code
 *
 */
int createPacketCache(uint32_t maxSize, PacketCache **packetCache);

/**
 * @brief Cleans the packet cache
 *
 * @par    packetCache = packet_cache to use
 * @par    packetInfo  = returns PORTMASTER_PACKET_INFO to free
 * @par    packet      = returns void to free
 * @return error code
 *
 */
int cleanPacketCache(PacketCache *packetCache, PortmasterPacketInfo **packetInfo, void **packet);

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
int teardownPacketCache(PacketCache *packetCache);

/**
 * @brief Registers a packet
 *
 * @par    packetCache = packetCache to use
 * @par    packetInfo  = pointer to packetInfo
 * @par    packet      = pointer to packet
 * @return new packet ID
 *
 */
uint32_t registerPacket(PacketCache *packetCache, PortmasterPacketInfo *packetInfo, void *packet, size_t packetLength);

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
int retrievePacket(PacketCache *packetCache, uint32_t packetID, PortmasterPacketInfo **packetInfoPtr, void **packet, size_t *packetLength);

/**
 * @brief Retrieves a packet from list, if it exists.
 *
 * @par    packetCache = packetCache to use
 * @par    packetID    = registered packet ID
 * @par    packet      = double pointer for packet return
 * @return error code
 *
 */
int getPacket(PacketCache *packetCache, uint32_t packetID, void **packet, size_t *packetLength);

#endif
