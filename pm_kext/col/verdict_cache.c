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

#include "pm_kernel.h"
#include "verdict_cache.h"
#include "pm_utils.h"
#include "pm_debug.h"

/**
 * @brief Initializes the verdict cache
 *
 * @par    max_size      = size of cache
 * @par    verdict_cache = returns new verdict_cache_t
 * @return error code
 *
 */
int create_verdict_cache(UINT32 max_size, verdict_cache_t** verdict_cache) {
    verdict_cache_t* new_verdict_cache;

    if (!max_size) {
        return 1;
    }
    new_verdict_cache= _ALLOC(sizeof(verdict_cache_t), 1);
    if (!new_verdict_cache) {
        return 1;
    }

    new_verdict_cache->size = 0;
    new_verdict_cache->max_size = max_size;
    *verdict_cache = new_verdict_cache;

    return 0;
}

/**
 * @brief Cleans the verdict cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = returns portmaster_packet_info to free
 * @return error code
 *
 */
int clean_verdict_cache(verdict_cache_t* verdict_cache, pportmaster_packet_info* packet_info) {
    if (!verdict_cache) {
        return 1;
    }

    if (verdict_cache->size <= verdict_cache->max_size) {
        return 1;
    }

    if (verdict_cache->tail) {
        // get last item
        verdict_cache_item_t* last_item = verdict_cache->tail;

        // remove from list
        if (last_item->prev) {
            // reconnect tail if there is an item left
            verdict_cache->tail = last_item->prev;
            // delete next of new last item
            last_item->prev->next = NULL;
        } else {
            // reset tail (list is empty!)
            verdict_cache->tail = NULL;
        }

        // set return value
        *packet_info = last_item->packet_info;

        // free
        _FREE(last_item);
        verdict_cache->size--;

        return 0;
    }

    return 1;
}


/**
 * @brief Tears down the verdict cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @return error code
 *
 */
int teardown_verdict_cache(verdict_cache_t* verdict_cache) {
    // FIXME: implement
    return 0;
}

/**
 * @brief Adds verdict to cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
int add_verdict(verdict_cache_t* verdict_cache, pportmaster_packet_info packet_info, verdict_t verdict) {
    verdict_cache_item_t *new_item;
    if (!verdict_cache || !packet_info || !verdict) {
        ERR("add_verdict NULL pointer exception verdict_cache=0p%Xp, packet_info=0p%Xp, verdict=0p%Xp ", verdict_cache, packet_info, verdict);
        return 1;
    }

    new_item = _ALLOC(sizeof(verdict_cache_item_t), 1);
    if(!new_item) {
        ERR("add_verdict tried to add NULL-Pointer verdict");
        return 2;
    }

    new_item->packet_info = packet_info;
    new_item->verdict = verdict;

    // insert as first item
    if (verdict_cache->head) {
        new_item->next = verdict_cache->head;
        verdict_cache->head->prev = new_item;
    }
    verdict_cache->head = new_item;

    // set tail if only item
    if (!verdict_cache->tail) {
        verdict_cache->tail = new_item;
    }

    verdict_cache->size++;
    return 0;
}

/**
 * @brief Checks packet for verdict
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @return verdict
 *
 */
verdict_t check_verdict(verdict_cache_t* verdict_cache, pportmaster_packet_info packet_info) {
    verdict_cache_item_t *item;

    if (!verdict_cache || !packet_info) {
        ERR("verdict_cache 0p%xp or packet_info 0p%xp was null", verdict_cache, packet_info);
        return PORTMASTER_VERDICT_ERROR;
    }

    // check if list is empty
    if (!verdict_cache->head) {
        INFO("verdict_cache was empty");
        return PORTMASTER_VERDICT_GET;
    }

    // check first item
    if (compare_full_packet_info(packet_info, verdict_cache->head->packet_info)) {
        DEBUG("compare_full_packet_info sucessful");
        return verdict_cache->head->verdict;
    }

    // check the rest of the list
    item = verdict_cache->head->next;
    while (item) {
        if (compare_full_packet_info(packet_info, item->packet_info)) {
            // pull item to front
            if (item->next) {
                // connect previous and next items
                item->prev->next = item->next;
                item->next->prev = item->prev;
            } else {
                // connect new last item with list tail
                item->prev->next = NULL;
                verdict_cache->tail = item->prev;
            }
            // insert in front
            item->prev = NULL;
            item->next = verdict_cache->head;
            verdict_cache->head->prev = item;
            verdict_cache->head = item;

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
 * @par    packet_info   = pointer to packet_info
 * @par    redir_info   = double pointer to packet_info (return value)
 * @par    verdict       = pointer to verdict (return value)
 * @return error code
 *
 */
verdict_t check_reverse_redir(verdict_cache_t* verdict_cache, pportmaster_packet_info packet_info, pportmaster_packet_info* redir_info) {
    verdict_cache_item_t *item;
    if (!verdict_cache || !packet_info || !redir_info) {
        return PORTMASTER_VERDICT_GET;
    }

    // check if list is empty
    if (!verdict_cache->head) {
        return PORTMASTER_VERDICT_GET;
    }

    // check first item
    if (compare_reverse_redir_packet_info(verdict_cache->head->packet_info, packet_info)) {
        *redir_info = verdict_cache->head->packet_info;
        return verdict_cache->head->verdict;
    }

    // check the rest of the list
    item = verdict_cache->head->next;
    while (item) {
        if (compare_reverse_redir_packet_info(item->packet_info, packet_info)) {

            // pull item to front
            if (item->next) {
                // connect previous and next items
                item->prev->next = item->next;
                item->next->prev = item->prev;
            } else {
                // connect new last item with list tail
                item->prev->next = NULL;
                verdict_cache->tail = item->prev;
            }
            // insert in front
            item->prev = NULL;
            item->next = verdict_cache->head;
            verdict_cache->head->prev = item;
            verdict_cache->head = item;

            // set return value
            *redir_info = item->packet_info;
            return item->verdict;
        }
        item = item->next;
    }

    return PORTMASTER_VERDICT_GET;
}
