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

#include <intsafe.h>
#define uint16_t UINT16
#define uint32_t UINT32
#define uint64_t UINT64

typedef struct packet_cache_item packet_cache_item_t;
struct packet_cache_item {
    packet_cache_item_t* prev;
    packet_cache_item_t* next;

    uint32_t packet_id;
    pportmaster_packet_info packet_info;
    void* packet;
    size_t packet_len;
    /*
    COMPARTMENT_ID compartmentId;
    IF_INDEX interfaceIndex;
    IF_INDEX subInterfaceIndex;
    */
};

typedef struct packet_cache {
    uint32_t size;
    uint32_t max_size;
    uint32_t next_packet_id;
    packet_cache_item_t* head;
    packet_cache_item_t* tail;
} packet_cache_t;


extern packet_cache_t* packetCache;
extern KSPIN_LOCK packetCacheLock;


/**
 * @brief Initializes the packet cache
 *
 * @par    max_size     = size of cache
 * @par    packet_cache = returns new packet_cache_t
 * @return error code
 *
 */
int create_packet_cache(uint32_t max_size, packet_cache_t** packet_cache);

/**
 * @brief Cleans the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_info  = returns PORTMASTER_PACKET_INFO to free
 * @par    packet       = returns void to free
 * @return error code
 *
 */
int clean_packet_cache(packet_cache_t* packet_cache, pportmaster_packet_info * packet_info, void** packet);

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
int teardown_packet_cache(packet_cache_t* packet_cache);

/**
 * @brief Registers a packet
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_info  = pointer to packet_info
 * @par    packet       = pointer to packet
 * @return new packet ID
 *
 */
uint32_t register_packet(packet_cache_t* packet_cache, pportmaster_packet_info  packet_info, void* packet, size_t packet_len);

/**
 * @brief Retrieves and deletes a packet from list, if it exsists.
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_id    = registered packet ID
 * @par    packet_info  = double pointer for packet_info return
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
int retrieve_packet(packet_cache_t* packet_cache, uint32_t packet_id, pportmaster_packet_info * packet_info, void** packet, size_t* packet_len);

/**
 * @brief Retrieves a packet from list, if it exsists.
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_id    = registered packet ID
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
int get_packet(packet_cache_t* packet_cache, uint32_t packet_id, void** packet, size_t* packet_len);

#endif
