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


typedef struct verdict_cache_item verdict_cache_item_t;
struct verdict_cache_item {
    verdict_cache_item_t* prev;
    verdict_cache_item_t* next;

    portmaster_packet_info* packet_info;
    verdict_t verdict;
};

typedef struct verdict_cache {
    UINT32 size;
    UINT32 max_size;
    verdict_cache_item_t* head;
    verdict_cache_item_t* tail;
} verdict_cache_t;

/**
 * @brief Initializes the verdict cache
 *
 * @par    max_size      = size of cache
 * @par    verdict_cache = returns new verdict_cache_t
 * @return error code
 *
 */
extern int create_verdict_cache(UINT32 max_size, verdict_cache_t** verdict_cache);


/**
 * @brief Cleans the verdict cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = returns portmaster_packet_info to free
 * @return error code
 *
 */
extern int clean_verdict_cache(verdict_cache_t* verdict_cache, portmaster_packet_info** packet_info);

/**
 * @brief Remove all items from verdict cache
 *
 * @par    verdict_cache = verdict_cache to use
 *
 */
void clear_all_entries_from_verdict_cache(verdict_cache_t* verdict_cache);

/**
 * @brief Tears down the verdict cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @return error code
 *
 */
extern int teardown_verdict_cache(verdict_cache_t* verdict_cache);

/**
 * @brief Adds verdict to cache
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @par    verdict       = verdict to save
 * @return error code
 *
 */
extern int add_verdict(verdict_cache_t* verdict_cache, portmaster_packet_info* packet_info, verdict_t verdict);

/**
 * @brief Checks packet for verdict
 *
 * @par    verdict_cache = verdict_cache to use
 * @par    packet_info   = pointer to packet_info
 * @return verdict
 *
 */
extern verdict_t check_verdict(verdict_cache_t* verdict_cache, portmaster_packet_info* packet_info);

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
extern verdict_t check_reverse_redir(verdict_cache_t* verdict_cache, portmaster_packet_info* packet_info, portmaster_packet_info** redir_info);

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
