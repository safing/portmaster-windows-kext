/*
 *  Name:        pm_netbuffer.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation for handling windows netbuffers
 *               like coping memory from networkstack to kernel
 *               https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ndis/ns-ndis-_net_buffer
 *
 *  Scope:       Kernelmode
 */

#include "pm_kernel.h"
#include "pm_utils.h"
#define LOGGER_NAME "pm_netbuffer"
#include "pm_debug.h"

#include "pm_common.h"


/*****************************************************************
 Static Variables to handle access to netbuffers
 *****************************************************************/
static NDIS_HANDLE nbl_pool_handle = NULL;      //Handle for NetBufferList
static NDIS_HANDLE nb_pool_handle = NULL;       //Handle for one NetBuffer


/*****************************************************************
 Helpers
 *****************************************************************/
/*
 * Initializes pool for  netbuffers
 * Called at DriverEntry
 */
NTSTATUS init_netbufferpool() {
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_params;
    NET_BUFFER_POOL_PARAMETERS nb_pool_params;

    // Create a NET_BUFFER_LIST pool handle.
    RtlZeroMemory(&nbl_pool_params, sizeof(nbl_pool_params));
    nbl_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_params.Header.Revision =
        NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_params.Header.Size = sizeof(nbl_pool_params);
    nbl_pool_params.fAllocateNetBuffer = TRUE;
    nbl_pool_params.PoolTag = PORTMASTER_TAG;
    nbl_pool_params.DataSize = 0;
    nbl_pool_handle = NdisAllocateNetBufferListPool(NULL, &nbl_pool_params);
    if (nbl_pool_handle == NULL) {
        ERR("failed to allocate net buffer list pool");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Create a NET_BUFFER pool handle.
    RtlZeroMemory(&nb_pool_params, sizeof(nb_pool_params));
    nb_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nb_pool_params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.Header.Size =
        NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.PoolTag = PORTMASTER_TAG;
    nb_pool_params.DataSize = 0;
    nb_pool_handle = NdisAllocateNetBufferPool(NULL, &nb_pool_params);
    if (nb_pool_handle == NULL) {
        ERR("failed to allocate net buffer pool");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    INFO("init_netbufferpool OK");
    return STATUS_SUCCESS;
}

/*
 * Frees the netbufferpool
 * Called at DriverUnload
 */
void free_netbufferpool() {
    if (nbl_pool_handle != NULL) {
        NdisFreeNetBufferListPool(nbl_pool_handle);
    }
    if (nb_pool_handle != NULL) {
        NdisFreeNetBufferPool(nb_pool_handle);
    }
    INFO("free_netbufferpool OK");
}

/*****************************************************************
 Acutal Netbuffer Handling
 *****************************************************************/
/*
 * Wraps packet data into netbuffer
 * Required for Sending / Injecting packets
 * packet_data: pointer to packet (Endianness must be set correctly at this level)
 * packet_len: Length of packet in bytes
 * Returns
 *    PNET_BUFFER_LIST*: packet to be sent
 *    NTSTATUS
 * Called by redir and respondWithVerdict
 */
NTSTATUS wrap_packet_data_in_nb(void* packet_data, int packet_len, PNET_BUFFER_LIST* nbl) {
    PMDL mdl;
    PNET_BUFFER_LIST buffers;
    NTSTATUS status;

    // sanity check
    if (!packet_data || packet_len == 0 || !nbl) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    mdl = IoAllocateMdl(packet_data, packet_len, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        ERR("failed to allocate MDL for reinjected packet");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(mdl);
    status = FwpsAllocateNetBufferAndNetBufferList0(nbl_pool_handle, 0, 0, mdl, 0, packet_len, &buffers);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create NET_BUFFER_LIST for reinjected packet");
        IoFreeMdl(mdl);
        return status;
    }
    *nbl = buffers;

    return STATUS_SUCCESS;
}

/*
 * "Borrows" data from netbuffer without actually coping it
 * This is faster, but does not always succeed.
 * Called by classifyAll.
 */
NTSTATUS borrow_packet_data_from_nb(PNET_BUFFER nb, ULONG bytesNeeded, void** data) {
    PVOID ptr;

    // sanity check
    if (!nb || !data) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    ptr = NdisGetDataBuffer(nb, bytesNeeded, NULL, 1, 0);
    if (ptr != NULL) {
        *data = ptr;
        return STATUS_SUCCESS;
    }

    return STATUS_INTERNAL_ERROR;
}

/*
 * copies packet data from netbuffer "nb" to "data" up to the size "maxBytes"
 * acutal bytes copied is stored in "data_len"
 * returns NTSTATUS
 * Called by classifyAll and redir_from_callout if "borrow_packet_data_from_nb" fails
 *
 * NET_BUFFER_LIST can hold multiple NET_BUFFER in rare edge cases. Ignoring these is ok for now.
 * TODO: handle these cases.
 */
NTSTATUS copy_packet_data_from_nb(PNET_BUFFER nb, ULONG maxBytes, void** data, ULONG* data_len) {
    PVOID ptr;
    *data_len = NET_BUFFER_DATA_LENGTH(nb);

    // sanity check
    if (!nb || !data || !data_len) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if (maxBytes == 0 || maxBytes > *data_len) {
        maxBytes = *data_len;
    } else {
        *data_len = maxBytes;
    }

    *data = portmaster_malloc(maxBytes, FALSE);
    if (*data == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    //Copy data from NET_BUFFER
    ptr = NdisGetDataBuffer(nb, maxBytes, NULL, 1, 0);
    if (ptr != NULL) {
        // Contiguous (common) case:
        RtlCopyMemory(*data, ptr, maxBytes);
    } else {
        // Non-contigious case:
        ptr = NdisGetDataBuffer(nb, maxBytes, *data, 1, 0);
        if (ptr == NULL) {
            return STATUS_INTERNAL_ERROR;
        }
    }

    return STATUS_SUCCESS;
}
