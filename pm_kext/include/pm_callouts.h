/*
 *  Name:        pm_callouts.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declaration of callouts, i.e. functions that are
 *               called from the kernel if a net traffic filter matches.
 *               Filters and callouts are registered in "pm_register.c"
 *
 *  Scope:       Kernelmode
 */

#ifndef WFPDriver_H
#define WFPDriver_H

#define NDIS61 1                // Need to declare this to compile WFP stuff on Win7, I'm not sure why

#include "Ntifs.h"
#include <ntddk.h>              // Windows Driver Development Kit
#include <wdf.h>                // Windows Driver Foundation

#pragma warning(push)
#pragma warning(disable: 4201)  // Disable "Nameless struct/union" compiler warning for fwpsk.h only!
#include <fwpsk.h>              // Functions and enumerated types used to implement callouts in kernel mode
#pragma warning(pop)            // Re-enable "Nameless struct/union" compiler warning

#include <fwpmk.h>              // Functions used for managing IKE and AuthIP main mode (MM) policy and security associations
#include <fwpvi.h>              // Mappings of OS specific function versions (i.e. fn's that end in 0 or 1)
#include <guiddef.h>            // Used to define GUID's
#include <initguid.h>           // Used to define GUID's
#include "devguid.h"

#endif // include guard


#ifndef SYS_CALLOUTS_H
#define SYS_CALLOUTS_H

#include "verdict_cache.h"


// /*
//  * IPv4/IPv6/ICMP/ICMPv6/TCP/UDP header definitions.
//  */
// typedef struct {
//     UINT8  HdrLength:4;
//     UINT8  Version:4;
//     UINT8  TOS;
//     UINT16 Length;
//     UINT16 Id;
//     UINT16 FragOff;
//     UINT8  TTL;
//     UINT8  Protocol;
//     UINT16 Checksum;
//     UINT32 SrcAddr;
//     UINT32 DstAddr;
// } IPHeader, *PIPHeader;

NTSTATUS initCalloutStructure();

void classifyInboundIPv4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut);

void classifyOutboundIPv4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut);

void classifyInboundIPv6(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut);

void classifyOutboundIPv6(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS genericNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID * filterKey,
    const FWPS_FILTER * filter);

void respondWithVerdict(UINT32 id, verdict_t verdict);
void redirect(PortmasterPacketInfo *packetInfo, PortmasterPacketInfo *redirInfo, void* packet, size_t packetLength, BOOL dns);
NTSTATUS genericFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext);
void destroyCalloutStructure();

#endif // include guard
