/*
 *  Name:        pm_utils.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utility-functions
 *
 *  Scope:       Kernelmode
 */

#ifndef __PM_UTILS_H__
#define __PM_UTILS_H__

#define PORTMASTER_TAG                           'saMP'

extern PVOID portmaster_malloc(SIZE_T size, BOOL paged);
extern VOID portmaster_free(PVOID ptr);

extern VOID calc_ipv4_checksum(void* data, int len, BOOL calc_transport);
extern VOID calc_ipv6_checksum(void* data, int len, BOOL calc_transport);

/**
 * @brief Compares two portmaster_packet_info for full equality
 *
 * @par    a  = portmaster_packet_info to compare
 * @par    b  = portmaster_packet_info to compare
 * @return equality (bool)
 *
 */
extern int compare_full_packet_info(portmaster_packet_info* a, portmaster_packet_info* b);

/**
 * @brief Compares two portmaster_packet_info for local adress equality
 *
 * @par    a  = portmaster_packet_info to compare
 * @par    b  = portmaster_packet_info to compare
 * @return equality (bool)
 *
 */
extern int compare_reverse_redir_packet_info(portmaster_packet_info* original, portmaster_packet_info* current);

/**
 * @brief Compares two portmaster_packet_info for remote address equality
 *
 * @par    a  = portmaster_packet_info to compare
 * @par    b  = portmaster_packet_info to compare
 * @return equality (bool)
 *
 */
extern int compare_remote_packet_info(portmaster_packet_info* a, portmaster_packet_info* b);

/**
 * @brief Checks if the IPv4 address is a loopback address
 *
 * @par    addr = IPv4 address
 * @return is loopback (bool)
 *
 */
BOOL is_ipv4_loopback(UINT32 addr);

/**
 * @brief Checks if the IPv6 address is a loopback address
 *
 * @par    addr = IPv6 address (the size of the array needs to be no less then 4)
 * @return is loopback (bool)
 *
 */
BOOL is_ipv6_loopback(UINT32 *addr);

/**
 * @brief Checks if the paket has loopack ip address
 *
 * @par    packet = the packet to be checked 
 * @return is loopback (bool)
 *
 */
BOOL is_packet_loopback(pportmaster_packet_info packet);

#endif

#ifndef DYN_ALLOC_FREE
#define DYN_ALLOC_FREE

#ifdef BUILD_ENV_DRIVER

#define _ALLOC(element_size, n_of_elements) portmaster_malloc(element_size*n_of_elements, FALSE)
#define _FREE(p_element) portmaster_free(p_element)

#else

#define _ALLOC(element_size, n_of_elements) calloc(element_size, n_of_elements)
#define _FREE(p_element) free(p_element)

#endif
#endif
