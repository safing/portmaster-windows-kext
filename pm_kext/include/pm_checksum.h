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

UINT32 checksumAdd(void* data, size_t len);
UINT16 checksumFinish(UINT32 sum);

void calcIPv4Checksum(void *data, size_t len, BOOL calcTransport);
void calcIPv6Checksum(void *data, size_t len, BOOL calcTransport);
size_t calcIPv4HeaderSize(void *data, size_t len);
size_t calcIPv6HeaderSize(void *data, size_t len, UINT8* returnProtocol);

#endif  //include guard
