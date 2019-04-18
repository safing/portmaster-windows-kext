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

extern NTSTATUS init_netbufferpool();
extern void free_netbufferpool();
NTSTATUS wrap_packet_data_in_nb(void* packet_data, int packet_len, PNET_BUFFER_LIST* nbl);
NTSTATUS copy_packet_data_from_nb(PNET_BUFFER nb, ULONG maxBytes, void** data, ULONG* data_len);
NTSTATUS borrow_packet_data_from_nb(PNET_BUFFER nb, ULONG bytesNeeded, void** data);

#endif
