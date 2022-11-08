/*
 *  Name:        pm_utils.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utility-functions
 *
 *  Scope:       Kernelmode
 */

#ifndef PM_UTILS_H
#define PM_UTILS_H

#include "pm_kernel.h"

#define PORTMASTER_TAG                           'saMP'

void *portmasterMalloc(size_t size, bool paged);
void portmasterFree(void *ptr);

/**
 * @brief Compares two PortmasterPacketInfo for full equality
 *
 * @par    a  = Pointer to PortmasterPacketInfo to compare
 * @par    b  = Pointer to PortmasterPacketInfo to compare
 * @return equality (bool)
 *
 */
bool compareFullPacketInfo(PortmasterPacketInfo *a, PortmasterPacketInfo *b);

/**
 * @brief Compares two PortmasterPacketInfo for local address equality
 *
 * @par    a  = Pointer to PortmasterPacketInfo to compare
 * @par    b  = Pointer to PortmasterPacketInfo to compare
 * @return equality (bool)
 *
 */
bool compareReverseRedirPacketInfo(PortmasterPacketInfo *original, PortmasterPacketInfo *current);

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
bool isIPv4Loopback(UINT32 addr);

/**
 * @brief Checks if the IPv6 address is a loopback address
 *
 * @par    addr = IPv6 address (the size of the array needs to be no less then 4)
 * @return is loopback (bool)
 *
 */
bool isIPv6Loopback(UINT32 *addr);

/**
 * @brief Checks if the packet has loopback ip address
 *
 * @par    packet = the packet to be checked 
 * @return is loopback (bool)
 *
 */
bool isPacketLoopback(PortmasterPacketInfo *packet);

/**
 * @brief Copy IPv6 address
 *
 * @par    inFixedValues = values structure from the callout
 * @par    idx = index of the that contains the ipv6 values
 * @par    ip = the array in which the values will be filled (length must be 4)
 * @return STATUS_SUCCESS on success
 *
 */
NTSTATUS copyIPv6(const FWPS_INCOMING_VALUES* inFixedValues, FWPS_FIELDS_OUTBOUND_IPPACKET_V6 idx, UINT32 *ip);

#endif // PM_UTILS_H
