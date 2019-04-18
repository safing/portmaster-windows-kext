/*
 *  Name:        pm_checksum.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declarations for checksum calculations in order
 *               to modify and reinject IP Packets
 *
 *  Scope:       Kernelmode
 */

#ifndef PM_CHECKSUM_H
#define PM_CHECKSUM_H

#include "pm_kernel.h"
#include "pm_debug.h"

extern UINT32 checksum_add(void* data, int len);
extern UINT16 checksum_finish(UINT32 sum);

extern VOID calc_ipv4_checksum(void* data, int len, BOOL calc_transport);
extern VOID calc_ipv6_checksum(void* data, int len, BOOL calc_transport);
extern ULONG calc_ipv4_header_size(void* data, size_t len);
extern ULONG calc_ipv6_header_size(void* data, size_t len, UINT8* return_protocol);

#endif  //include guard
