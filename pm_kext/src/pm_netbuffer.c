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
 Global Variables to handle access to net buffers
 *****************************************************************/
NDIS_HANDLE nblPoolHandle = NULL;      // Handle for NetBufferList
NDIS_HANDLE nbPoolHandle = NULL;       // Handle for one NetBuffer


/*****************************************************************
 Helpers
 *****************************************************************/
/*
 * Initializes pool for  netbuffers
 * Called at DriverEntry
 */
NTSTATUS initNetBufferPool() {
    // Create a NET_BUFFER_LIST pool handle.
    NET_BUFFER_LIST_POOL_PARAMETERS nblPoolParams;
    RtlZeroMemory(&nblPoolParams, sizeof(nblPoolParams));
    nblPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nblPoolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPoolParams.Header.Size = sizeof(nblPoolParams);
    nblPoolParams.fAllocateNetBuffer = TRUE;
    nblPoolParams.PoolTag = PORTMASTER_TAG;
    nblPoolParams.DataSize = 0;
    nblPoolHandle = NdisAllocateNetBufferListPool(NULL, &nblPoolParams);
    if (nblPoolHandle == NULL) {
        ERR("failed to allocate net buffer list pool");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Create a NET_BUFFER pool handle.
    NET_BUFFER_POOL_PARAMETERS nbPoolParams;
    RtlZeroMemory(&nbPoolParams, sizeof(nbPoolParams));
    nbPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbPoolParams.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPoolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPoolParams.PoolTag = PORTMASTER_TAG;
    nbPoolParams.DataSize = 0;
    nbPoolHandle = NdisAllocateNetBufferPool(NULL, &nbPoolParams);
    if (nbPoolHandle == NULL) {
        ERR("failed to allocate net buffer pool");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    INFO("initNetBufferPool OK");
    return STATUS_SUCCESS;
}

/*
 * Frees the NetBufferPool
 * Called at DriverUnload
 */
void freeNetBufferPool() {
    if (nblPoolHandle != NULL) {
        NdisFreeNetBufferListPool(nblPoolHandle);
    }
    if (nbPoolHandle != NULL) {
        NdisFreeNetBufferPool(nbPoolHandle);
    }
    INFO("freeNetBufferPool OK");
}

/*****************************************************************
 Acutal Netbuffer Handling
 *****************************************************************/
/*
 * Wraps packet data into netbuffer
 * Required for Sending / Injecting packets
 * packetData: pointer to packet (Endianness must be set correctly at this level)
 * packetLength: Length of packet in bytes
 * Returns
 *    PNET_BUFFER_LIST*: packet to be sent
 *    NTSTATUS
 * Called by redir and respondWithVerdict
 */
NTSTATUS wrapPacketDataInNB(void* packetData, size_t packetLength, PNET_BUFFER_LIST* nbl) {
    // sanity check
    if (!packetData || packetLength == 0 || !nbl) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    PMDL mdl = IoAllocateMdl(packetData, (ULONG)packetLength, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        ERR("failed to allocate MDL for reinjected packet");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(mdl);

    PNET_BUFFER_LIST buffers = NULL;
    NTSTATUS status = FwpsAllocateNetBufferAndNetBufferList0(nblPoolHandle, 0, 0, mdl, 0, packetLength, &buffers);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create NET_BUFFER_LIST for reinjected packet");
        IoFreeMdl(mdl);
        return status;
    }
    *nbl = buffers;

    return STATUS_SUCCESS;
}

/*
 * "Borrows" data from net buffer without actually coping it
 * This is faster, but does not always succeed.
 * Called by classifyAll.
 */
NTSTATUS borrowPacketDataFromNB(PNET_BUFFER nb, size_t bytesNeeded, void **data) {
    // sanity check
    if (!nb || !data) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    void *ptr = NdisGetDataBuffer(nb, (ULONG)bytesNeeded, NULL, 1, 0);
    if (ptr != NULL) {
        *data = ptr;
        return STATUS_SUCCESS;
    }

    return STATUS_INTERNAL_ERROR;
}

/*
 * copies packet data from net buffer "nb" to "data" up to the size "maxBytes"
 * actual bytes copied is stored in "dataLength"
 * returns NTSTATUS
 * Called by classifyAll and redir_from_callout if "borrow_packet_data_from_nb" fails
 *
 * NET_BUFFER_LIST can hold multiple NET_BUFFER in rare edge cases. Ignoring these is ok for now.
 * TODO: handle these cases.
 */
NTSTATUS copyPacketDataFromNB(PNET_BUFFER nb, size_t maxBytes, void **data, size_t *dataLength) {
    *dataLength = NET_BUFFER_DATA_LENGTH(nb);

    // sanity check
    if (!nb || !data || !dataLength) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    if (maxBytes == 0 || maxBytes > *dataLength) {
        maxBytes = *dataLength;
    } else {
        *dataLength = maxBytes;
    }

    *data = portmasterMalloc(maxBytes, FALSE);
    if (*data == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    //Copy data from NET_BUFFER
    void *ptr = NdisGetDataBuffer(nb, (ULONG)maxBytes, NULL, 1, 0);
    if (ptr != NULL) {
        // Contiguous (common) case:
        RtlCopyMemory(*data, ptr, maxBytes);
    } else {
        // Non-contigious case:
        ptr = NdisGetDataBuffer(nb, (ULONG)maxBytes, *data, 1, 0);
        if (ptr == NULL) {
            return STATUS_INTERNAL_ERROR;
        }
    }

    return STATUS_SUCCESS;
}
