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

void *portmasterMalloc(size_t size, BOOL paged);
void portmasterFree(void *ptr);

void calcIPv4Checksum(void *data, size_t len, BOOL calcTransport);
void calcIPv6Checksum(void *data, size_t len, BOOL calcTransport);

/**
 * @brief Compares two PortmasterPacketInfo for full equality
 *
 * @par    a  = Pointer to PortmasterPacketInfo to compare
 * @par    b  = Pointer to PortmasterPacketInfo to compare
 * @return equality (bool)
 *
 */
BOOL compareFullPacketInfo(PortmasterPacketInfo *a, PortmasterPacketInfo *b);

/**
 * @brief Compares two PortmasterPacketInfo for local address equality
 *
 * @par    a  = Pointer to PortmasterPacketInfo to compare
 * @par    b  = Pointer to PortmasterPacketInfo to compare
 * @return equality (bool)
 *
 */
BOOL compareReverseRedirPacketInfo(PortmasterPacketInfo *original, PortmasterPacketInfo *current);

/**
 * @brief Compares two portmaster_packet_info for remote address equality
 *
 * @par    a  = Pointer to PortmasterPacketInfo to compare
 * @par    b  = Pointer to PortmasterPacketInfo to compare
 * @return equality (bool)
 *
 */
int compareRemotePacketInfo(PortmasterPacketInfo *a, PortmasterPacketInfo *b);

/**
 * @brief Checks if the IPv4 address is a loopback address
 *
 * @par    addr = IPv4 address
 * @return is loopback (bool)
 *
 */
BOOL isIPv4Loopback(UINT32 addr);

/**
 * @brief Checks if the IPv6 address is a loopback address
 *
 * @par    addr = IPv6 address (the size of the array needs to be no less then 4)
 * @return is loopback (bool)
 *
 */
BOOL isIPv6Loopback(UINT32 *addr);

/**
 * @brief Checks if the packet has loopback ip address
 *
 * @par    packet = the packet to be checked 
 * @return is loopback (bool)
 *
 */
BOOL isPacketLoopback(PortmasterPacketInfo *packet);

#endif

#ifndef DYN_ALLOC_FREE
#define DYN_ALLOC_FREE

#ifdef BUILD_ENV_DRIVER

#define _ALLOC(element_size, n_of_elements) portmasterMalloc(element_size*n_of_elements, FALSE)
#define _FREE(p_element) portmasterFree(p_element)

#else

#define _ALLOC(element_size, n_of_elements) calloc(element_size, n_of_elements)
#define _FREE(p_element) free(p_element)

#endif
#endif
