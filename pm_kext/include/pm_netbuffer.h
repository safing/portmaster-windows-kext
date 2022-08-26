/*
 *  Name:        pm_netbuffer.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declarations for handling windows netbuffers
 *               like coping memory from networkstack to kernel
 *               https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ndis/ns-ndis-_net_buffer
 *
 *  Scope:       Kernelmode
 */

#ifndef __PM_NETBUFFER_H
#define __PM_NETBUFFER_H

NTSTATUS initNetBufferPool();
void freeNetBufferPool();
NTSTATUS wrapPacketDataInNB(void *packetData, size_t packetLen, PNET_BUFFER_LIST *nbl);
NTSTATUS copyPacketDataFromNB(PNET_BUFFER nb, size_t maxBytes, void **data, size_t *dataLength);
NTSTATUS borrowPacketDataFromNB(PNET_BUFFER nb, size_t bytesNeeded, void **data);

#endif
