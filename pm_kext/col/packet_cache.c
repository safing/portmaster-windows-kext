/*
 *  Name:        packet_cache.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of packet cache.  IP-Packets must be cached
 *               until we know what to do with them (block, drop, reinject).
 *               Caching Algorithm: Last In First Out (LIFO)
 *
 *  Scope:       Kernelmode
 *               (Userland for development)
 */

#define BUILD_ENV_DRIVER

#include <stdlib.h>
#include <limits.h>

#include "pm_kernel.h"
#include "pm_common.h"
#include "packet_cache.h"
#include "pm_utils.h"
#include "pm_debug.h"

/**
 * @brief Initializes the packet cache
 *
 * @par    max_size     = size of cache
 * @par    packet_cache = returns new packet_cache_t
 * @return error code
 *
 */
int create_packet_cache(uint32_t max_size, packet_cache_t** packet_cache) {
    packet_cache_t* new;

    if (!max_size) {
        ERR("create_packet_cache");
        return 1;
    }
    INFO("create_packet_cache with size %d", max_size);

    new = _ALLOC(sizeof(packet_cache_t), 1);
    if (!new) {
        return 1;
    }

    new->size = 0;
    new->max_size = max_size;
    new->next_packet_id = 1;
    *packet_cache = new;

    return 0;
}

/**
 * @brief Cleans the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_info  = returns PORTMASTER_PACKET_INFO to free
 * @par    packet       = returns void to free
 * @return error code
 *
 */
int clean_packet_cache(packet_cache_t* packet_cache, pportmaster_packet_info * packet_info, void** packet) {
    if(!packet_cache) {
        ERR("clean_packet_cache - invalid params");
        return 1;
    }

    if (packet_cache->size <= packet_cache->max_size) { // '<=' is correct ,-)
        INFO("clean_packet_cache - current size= %d, max_size=%d -> nothing to free", packet_cache->size, packet_cache->max_size);
        return 1;
    }
    
    INFO("clean_packet_cache - current size= %d, max_size=%d -> trying to drop last packet",  packet_cache->size, packet_cache->max_size);

    if (packet_cache->tail) {
        // get last item
        packet_cache_item_t* last_item = packet_cache->tail;

        INFO("clean_packet_cache - tail exists (size=%d)-> trying to free one packet", packet_cache->size);
        // remove from list
        if (last_item->prev) {
            // reconnect tail if there is an item left
            packet_cache->tail = last_item->prev;
            // delete next of new last item
            last_item->prev->next = NULL;
        } else {
            // reset tail (list is empty!)
            packet_cache->tail = NULL;
        }

        // set return value
        *packet_info = last_item->packet_info;
        *packet = last_item->packet;

        // free
        _FREE(last_item);
        packet_cache->size--;  // Decrement size, otherwise cache will become useless eventually 
                               // so that every packet will be dropped
        INFO("clean_packet_cache - item freed, size=%d", packet_cache->size);

        return 0;
    }

    return 1;
}

/**
 * @brief Tears down the packet cache
 *
 * @par    packet_cache = packet_cache to use
 * @return error code
 *
 */
int teardown_packet_cache(packet_cache_t* packet_cache) {
    // FIXME: implement
    WARN("teardown_packet_cache not yet implemented");
    return 0;
}

/**
 * @brief Registers a packet
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_info  = pointer to packet_info
 * @par    packet       = pointer to packet
 * @return new packet ID
 *
 */
uint32_t register_packet(packet_cache_t* packet_cache, pportmaster_packet_info  packet_info, void* packet, size_t packet_len) {
    packet_cache_item_t *new_item;
    DEBUG("register_packet called");
    if(!packet_cache || !packet_info || !packet) {
        ERR("register_packet - invalid params");
        return 0;
    }

    new_item = _ALLOC(sizeof(packet_cache_item_t), 1);
    if(!new_item) {
        ERR("register_packet - could not allocate new_item");
        return 0;
    }

    new_item->packet_id = packet_cache->next_packet_id++;
    // check for overflow
    if (packet_cache->next_packet_id >= ULONG_MAX) {
        packet_cache->next_packet_id = 1;
    }

    new_item->packet_info = packet_info;
    new_item->packet = packet;
    new_item->packet_len = packet_len;

    // insert as first item
    if (packet_cache->head) {
        new_item->next = packet_cache->head;
        packet_cache->head->prev = new_item;
    }
    packet_cache->head = new_item;

    // set tail if only item
    if (!packet_cache->tail) {
        packet_cache->tail = new_item;
    }

    packet_cache->size++;
    return new_item->packet_id;
}

/**
 * @brief Retrieves a packet, if it exsists. The returned packet and packet_info will be removed from the list.
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_id    = registered packet ID
 * @par    packet_info  = double pointer for packet_info return
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
int retrieve_packet(packet_cache_t* packet_cache, uint32_t packet_id, pportmaster_packet_info * packet_info, void** packet, size_t* packet_len) {
    packet_cache_item_t *item;
    item = packet_cache->head;
    DEBUG("retrieve_packet called");
    while (item) {
        if (packet_id == item->packet_id) {
            // set return values
            *packet_info = item->packet_info;
            *packet = item->packet;
            *packet_len = item->packet_len;

            // delete item
            if (item->prev) {
                item->prev->next = item->next;
            } else {
                packet_cache->head = item->next;
            }
            if (item->next) {
                item->next->prev = item->prev;
            } else {
                packet_cache->tail = item->prev;
            }

            // clean
            _FREE(item);
            packet_cache->size--;

            return 0;
        }
        item = item->next;
    }
    return 1;
}

/**
 * @brief Returns a packet, if it exsists. The list is not changed.
 *
 * @par    packet_cache = packet_cache to use
 * @par    packet_id    = registered packet ID
 * @par    packet       = double pointer for packet return
 * @return error code
 *
 */
int get_packet(packet_cache_t* packet_cache, uint32_t packet_id, void** packet, size_t* packet_len) {
    packet_cache_item_t *item;
    DEBUG("get_packet called");
    item = packet_cache->head;
    while (item) {
        if (packet_id == item->packet_id) {
            // set return values
            *packet = item->packet;
            *packet_len = item->packet_len;

            return 0;
        }
        item = item->next;
    }
    return 1;
}
