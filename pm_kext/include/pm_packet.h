/*
 *  Name:        pm_packet.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Packet redirect, generate and inject functionality
 *
 *  Scope:       Kernelmode
 */

#ifndef PM_PACKET_H
#define PM_PACKET_H

#include "pm_kernel.h"
#include "pm_common.h"

#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Initialize inject handles
 *
 * @return STATUS_SUCCESS on success
 *
 */
NTSTATUS initializeInjectHandles();

/**
 * @brief Destroy inject handles
 *
 * @return void
 *
 */
void destroyInjectHandles();

/**
 * @brief Gets the appropriate inject handle for a packet
 * 
 * @par    packetInfo -> info for the packet
 * @return inject handle
 *
 */
HANDLE getInjectionHandleForPacket(PortmasterPacketInfo *packetInfo);
HANDLE getBlockedPacketInjectHandle(PortmasterPacketInfo *packetInfo);

NTSTATUS injectPacketWithHandle(HANDLE handle, PortmasterPacketInfo *packetInfo, UINT8 direction, void *packet, size_t packetLength);

/**
 * @brief Injects a packet in the network loop
 * 
 * @par    packetInfo -> info for the packet
 * @par    direction -> direction on which the packet should be inject inbound or outbound
 * @par    packet -> raw packet data
 * @par    packetLength -> size of the raw packet data
 * @par    forceSend -> force send even for incoming packets
 * @return STATUS_SUCCESS on success
 *
 */
NTSTATUS injectPacket(PortmasterPacketInfo *packetInfo, UINT8 direction, void *packet, size_t packetLength);

/**
 * @brief Copies a packet from net buffer and injects it
 * 
 * @par    packetInfo -> info for the packet
 * @par    nb -> net buffer that contains the packet
 * @par    ipHeaderSize -> size of the ip header
 * @return void
 *
 */
void copyAndInject(PortmasterPacketInfo* packetInfo, PNET_BUFFER nb, UINT32 ipHeaderSize);

/**
 * @brief Sends a block packet. RST for tcp and ICMP block for everything else
 * 
 * @par    packetInfo -> info for the packet
 * @par    originalPacket -> raw packet data
 * @par    originalPacketLength -> raw packet data length
  * @return STATUS_SUCCESS on success
 *
 */
NTSTATUS sendBlockPacket(PortmasterPacketInfo* packetInfo, void* originalPacket, size_t originalPacketLength);

/**
 * @brief Sends a block packet to be used from callout. RST for tcp and ICMP block for everything else
 * 
 * @par    packetInfo -> info for the packet
 * @par    nb -> net buffer that contains the packet data
 * @par    ipHeaderSize -> size of ip header
  * @return STATUS_SUCCESS on success
 *
 */
NTSTATUS sendBlockPacketFromCallout(PortmasterPacketInfo* packetInfo, PNET_BUFFER nb, size_t ipHeaderSize);

/**
 * @brief Redirects a packet 
 * 
 * @par    packetInfo -> info for the packet
 * @par    redirInfo -> redirect info for the packet
 * @par    packet -> raw packet data
 * @par    packetLength -> raw packet data length
 * @par    dns -> is dns request
  * @return STATUS_SUCCESS on success
 *
 */
void redirectPacket(PortmasterPacketInfo *packetInfo, PortmasterPacketInfo *redirInfo, void *packet, size_t packetLength, bool dns);

/**
 * @brief Redirects a packet to be used from callout
 * 
 * @par    packetInfo -> info for the packet
 * @par    redirInfo -> redirect info for the packet
 * @par    nb -> net buffer that contains packet data
 * @par    ipHeaderSize -> size of ip header
 * @par    dns -> is dns request
  * @return STATUS_SUCCESS on success
 *
 */
void redirectPacketFromCallout(PortmasterPacketInfo *packetInfo, PortmasterPacketInfo *redirInfo, PNET_BUFFER nb, size_t ipHeaderSize, bool dns);

#endif // PM_PACKET_H