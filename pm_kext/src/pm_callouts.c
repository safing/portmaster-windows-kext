/*
 *  Name:        pm_callouts.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of callouts, i.e. functions that are
 *               called from the kernel if a net traffic filter matches.
 *               Filters and callouts are registered in "pm_register.c"
 *
 *  Scope:       Kernelmode
 */


#include "pm_kernel.h"
#include "pm_callouts.h"
#include "pm_netbuffer.h"
#define LOGGER_NAME "pm_callouts"
#include "pm_debug.h"
#include "pm_checksum.h"
#include "pm_packet.h"

#include "pm_utils.h"

/******************************************************************
 * Global (static) data structures
 ******************************************************************/
static VerdictCache *verdictCacheV4;
static VerdictCache *verdictCacheV6;

static PacketCache *packetCache = NULL;

/******************************************************************
 * Helper Functions
 ******************************************************************/

NTSTATUS initCalloutStructure() {
    int rc = verdictCacheCreate(PM_VERDICT_CACHE_SIZE, &verdictCacheV4);
    if (rc != 0) {
        return STATUS_INTERNAL_ERROR;
    }

    rc = verdictCacheCreate(PM_VERDICT_CACHE_SIZE, &verdictCacheV6);
    if (rc != 0) {
        return STATUS_INTERNAL_ERROR;
    }

    rc = packetCacheCreate(PM_PACKET_CACHE_SIZE, &packetCache);
    if (rc != 0) {
        return STATUS_INTERNAL_ERROR;
    }

    initializeInjectHandles();

    return STATUS_SUCCESS;
}

void destroyCalloutStructure() {
    destroyInjectHandles();
}

NTSTATUS genericNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID * filterKey,
    const FWPS_FILTER * filter) {

    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType) {
        case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
            INFO("A new filter has registered a callout as its action");
            break;
        case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
            INFO("A filter has just been deleted");
            break;
    }
    return STATUS_SUCCESS;
}

NTSTATUS genericFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
    return STATUS_SUCCESS;
}

void respondWithVerdict(UINT32 id, verdict_t verdict) {
    // sanity check
    if (id == 0 || verdict == 0) {
        ERR("Invalid parameters");
        return;
    }

    bool temporary = false;
    if (verdict < 0) {
        temporary = true;
        verdict = verdict * -1;
    }

    INFO("Trying to retrieve packet");


    PortmasterPacketInfo *packetInfo = NULL;
    void *packet = NULL;
    size_t packetLength = 0;
    int rc = packetCacheRetrieve(packetCache, id, &packetInfo, &packet, &packetLength);
   

    if (rc != 0) {
        // packet id was not in packet cache
        INFO("received verdict response for unknown packet id: %u", id);
        return;
    }
    INFO("received verdict response for packet id: %u", id);

    //Store permanent verdicts in verdictCache
    if (!temporary) {
        VerdictCache *verdictCache = verdictCacheV4;

        // Switch to IPv6 cache and lock if needed.
        if (packetInfo->ipV6) {
            verdictCache = verdictCacheV6;
        }

        // Add to verdict cache
        PortmasterPacketInfo *packetInfoToFree = NULL;
        rc = verdictCacheAdd(verdictCache, packetInfo, verdict, &packetInfoToFree);

        // Free returned packet info.
        if (packetInfoToFree != NULL) {
            portmasterFree(packetInfoToFree);
        }

        //If verdict could not be added, drop and free the packet
        if (rc != 0) {
            portmasterFree(packetInfo);
            portmasterFree(packet);
            return;
        }
    }

    //Handle Packet according to Verdict
    switch (verdict) {
        case PORTMASTER_VERDICT_DROP:
            INFO("PORTMASTER_VERDICT_DROP: %s", printPacketInfo(packetInfo));
            portmasterFree(packet);
            return;
        case PORTMASTER_VERDICT_BLOCK:
            INFO("PORTMASTER_VERDICT_BLOCK: %s", printPacketInfo(packetInfo));
            sendBlockPacket(packetInfo, packet, packetLength);
            portmasterFree(packet);
            return;
        case PORTMASTER_VERDICT_ACCEPT:
            DEBUG("PORTMASTER_VERDICT_ACCEPT: %s", printPacketInfo(packetInfo));
            break; // ACCEPT
        case PORTMASTER_VERDICT_REDIR_DNS:
            INFO("PORTMASTER_VERDICT_REDIR_DNS: %s", printPacketInfo(packetInfo));
            redirectPacket(packetInfo, packetInfo, packet, packetLength, true);
            // redirect will free the packet memory
            return;
        case PORTMASTER_VERDICT_REDIR_TUNNEL:
            INFO("PORTMASTER_VERDICT_REDIR_TUNNEL: %s", printPacketInfo(packetInfo));
            redirectPacket(packetInfo, packetInfo, packet, packetLength, false);
            // redirect will free the packet memory
            return;
        default:
            WARN("unknown verdict: 0x%x {%s}", printPacketInfo(packetInfo));
            portmasterFree(packet);
            return;
    }

    // Fix checksums, including TCP/UDP.
    if (!packetInfo->ipV6) {
        calcIPv4Checksum(packet, packetLength, true);
    } else {
        calcIPv6Checksum(packet, packetLength, true);
    }

    NTSTATUS status = injectPacket(packetInfo, packetInfo->direction, packet, packetLength); // this call will free the packet even if the inject fails

    if (!NT_SUCCESS(status)) {
        ERR("respondWithVerdict -> FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
    }

    // If verdict is temporary, free packetInfo
    if (temporary) {
        portmasterFree(packetInfo);
    }
    // otherwise, keep packetInfo because it is referenced by verdict_cache

    INFO("Good Bye respondWithVerdict");
}

PacketCache* getPacketCache() {
    return packetCache;
}

/******************************************************************
 * Classify Functions
 ******************************************************************/
FWP_ACTION_TYPE classifySingle(
    PortmasterPacketInfo* packetInfo,
    VerdictCache *verdictCache,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    PNET_BUFFER nb,
    UINT32 ipHeaderSize
    ) {
    NTSTATUS status = STATUS_SUCCESS;
    
    //Inbound traffic requires special treatment - dafuq?
    if (packetInfo->direction == DIRECTION_INBOUND) {
        status = NdisRetreatNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
        if (!NT_SUCCESS(status)) {
            ERR("failed to retreat net buffer data start");
            return FWP_ACTION_BLOCK;
        }
    }

#ifdef DEBUG_ON
    {
        void* data = NULL;
        status = borrowPacketDataFromNB(nb, ipHeaderSize, &data);
        if (NT_SUCCESS(status)) {
            IPv4Header* p = (IPv4Header*)data;
            DEBUG("[v6=%d, dir=%d] V=%d, HL=%d, TOS=%d, TL=%d, ID=%d, FRAGO=%d, TTL=%d, P=%d, SUM=%d, SRC=%d.%d.%d.%d, DST=%d.%d.%d.%d",
                packetInfo->ipV6,
                packetInfo->direction,
                p->Version, p->HdrLength, p->TOS,
                RtlUshortByteSwap(p->Length),
                RtlUshortByteSwap(p->Id),
                RtlUshortByteSwap(p->FragOff0),
                p->TTL, p->Protocol,
                RtlUshortByteSwap(p->Checksum),
                FORMAT_ADDR(RtlUlongByteSwap(p->SrcAddr)),
                FORMAT_ADDR(RtlUlongByteSwap(p->DstAddr)));
        }
    }
#endif // DEBUG

    bool copiedNBForPacketInfo = false;
    size_t dataLength = 0;
    void *data = NULL;
    status = borrowPacketDataFromNB(nb, ipHeaderSize + 4, &data);
    if (!NT_SUCCESS(status)) {
        size_t reqBytes = ipHeaderSize + 4;
        INFO("borrowPacketDataFromNB could not return IPHeader+4B, status=0x%X -> copyPacketDataFromNB", status);
        // TODO: if we start to use copyPacketDataFromNB here, free space afterwards!
        status = copyPacketDataFromNB(nb, reqBytes, &data, &dataLength);
        if (!NT_SUCCESS(status)) {
            ERR("copyPacketDataFromNB could not copy IP Header+4 bytes, status=x%X, BLOCK", status);
            return FWP_ACTION_BLOCK;
        }

        // check if we got enough data
        if (dataLength < reqBytes) {
            ERR("Requested %u bytes, but received %u bytes (ipV6=%i, protocol=%u, status=0x%X)", reqBytes, dataLength, packetInfo->ipV6, packetInfo->protocol, status);
            portmasterFree(data);
            return FWP_ACTION_BLOCK;
        }

        copiedNBForPacketInfo = true;
    }

    // get protocol
    if (packetInfo->ipV6) {
        packetInfo->protocol = ((UINT8*) data)[6];
    } else {
        packetInfo->protocol = ((UINT8*) data)[9];
    }

    // get ports
    UINT16 srcPort = 0;
    UINT16 dstPort = 0;
    switch (packetInfo->protocol) {
        case PROTOCOL_TCP:
        case PROTOCOL_UDP: // UDP
        case PROTOCOL_DCCP: // DCCP
        case PROTOCOL_UDPLite: // UDP Lite
            RtlCopyBytes((void*) &srcPort, (void*) ((UINT8*)data+ipHeaderSize), 2);
            srcPort = RtlUshortByteSwap(srcPort);
            RtlCopyBytes((void*) &dstPort, (void*) ((UINT8*)data+ipHeaderSize+2), 2);
            dstPort= RtlUshortByteSwap(dstPort);
            if (packetInfo->direction == DIRECTION_INBOUND) {
                packetInfo->localPort = dstPort;
                packetInfo->remotePort = srcPort;
            } else {
                packetInfo->localPort = srcPort;
                packetInfo->remotePort = dstPort;
            }
            break;
        default:
            packetInfo->localPort = 0;
            packetInfo->remotePort = 0;
    }

    // free if copied
    if (copiedNBForPacketInfo) {
        portmasterFree(data);
    }

    //Shift back
    if (packetInfo->direction == DIRECTION_INBOUND) {
        NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
    }

    // Set default verdict.

    // First check if the packet is a DNAT response.
    PortmasterPacketInfo* redirInfo = NULL;
    verdict_t verdict = verdictCacheGet(verdictCache, packetInfo, &redirInfo);


    switch (verdict) {
        case PORTMASTER_VERDICT_DROP:
            INFO("PORTMASTER_VERDICT_DROP: %s", printPacketInfo(packetInfo));
            return FWP_ACTION_BLOCK;

        case PORTMASTER_VERDICT_BLOCK:
            INFO("PORTMASTER_VERDICT_BLOCK: %s", printPacketInfo(packetInfo));
            sendBlockPacketFromCallout(packetInfo, nb, ipHeaderSize);
            return FWP_ACTION_BLOCK;

        case PORTMASTER_VERDICT_ACCEPT:
            INFO("PORTMASTER_VERDICT_ACCEPT: %s", printPacketInfo(packetInfo));
            return FWP_ACTION_PERMIT;

        case PORTMASTER_VERDICT_REDIR_DNS:
            INFO("PORTMASTER_VERDICT_REDIR_DNS: %s", printPacketInfo(packetInfo));
            redirectPacketFromCallout(packetInfo, redirInfo, nb, ipHeaderSize, true);
            return FWP_ACTION_NONE; // We use FWP_ACTION_NONE to signal classifyMultiple that the packet was already fully handled.

        case PORTMASTER_VERDICT_REDIR_TUNNEL:
            INFO("PORTMASTER_VERDICT_REDIR_TUNNEL: %s", printPacketInfo(packetInfo));
            redirectPacketFromCallout(packetInfo, redirInfo, nb, ipHeaderSize, false);
            return FWP_ACTION_NONE; // We use FWP_ACTION_NONE to signal classifyMultiple that the packet was already fully handled.

        case PORTMASTER_VERDICT_GET:
            INFO("PORTMASTER_VERDICT_GET: %s", printPacketInfo(packetInfo));
            // Continue with operation to send verdict request.

            // We will return FWP_ACTION_NONE to signal classifyMultiple that the packet was already fully handled.
            // classifyMultiple will block and absorb the packet for us.
            // We need to copy the packet here to continue.
            // Source: https://docs.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts
            break;

        case PORTMASTER_VERDICT_ERROR:
            ERR("PORTMASTER_VERDICT_ERROR");
            return FWP_ACTION_BLOCK;

        default:
            WARN("unknown verdict: 0x%x {%s}", printPacketInfo(packetInfo));
            return FWP_ACTION_BLOCK;
    }

    // Handle packet of unknown connection.
    {
        DataEntry *dentry = NULL;
        bool fastTracked = false;
        int rc = 0;

        // Get the process ID.
        if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
            packetInfo->processID = inMetaValues->processId;
        } else {
            packetInfo->processID = 0;
        }

        // Check if the packet is redirected to the Portmaster and can be fast-tracked.
        // TODO: Use this for all localhost communication.
        // TODO: Then, check the incoming part in the Portmaster together with the outgoing part.
        if (
            packetInfo->direction == DIRECTION_INBOUND &&
            (packetInfo->localPort == PORT_DNS ||
                packetInfo->localPort == PORT_PM_API ||
                packetInfo->localPort == PORT_PM_SPN_ENTRY) &&
            packetInfo->localIP[0] == packetInfo->remoteIP[0] &&
            packetInfo->localIP[1] == packetInfo->remoteIP[1] &&
            packetInfo->localIP[2] == packetInfo->remoteIP[2] &&
            packetInfo->localIP[3] == packetInfo->remoteIP[3]
        ) {
            fastTracked = true;
            packetInfo->flags |= PM_STATUS_FAST_TRACK_PERMITTED;

            INFO("Fast-tracking %s", printPacketInfo(packetInfo));
        } else {
            INFO("Getting verdict for %s", printPacketInfo(packetInfo));
        }

        // allocate queue entry and copy packetInfo
        dentry = portmasterMalloc(sizeof(DataEntry), false);
        if (!dentry) {
            ERR("Insufficient Resources for allocating dentry");
            return FWP_ACTION_NONE;
        }
        PortmasterPacketInfo *copiedPacketInfo = portmasterMalloc(sizeof(PortmasterPacketInfo), false);
        if (!copiedPacketInfo) {
            ERR("Insufficient Resources for allocating copiedPacketInfo");
            // TODO: free other allocated memory.
            return FWP_ACTION_NONE;
        }
        RtlCopyMemory(copiedPacketInfo, packetInfo, sizeof(PortmasterPacketInfo));
        dentry->packet = copiedPacketInfo;

        // If fast-tracked, add verdict to cache immediately.
        if (fastTracked) {
            // Add to verdict cache
            PortmasterPacketInfo *packetInfoToFree = NULL;
            rc = verdictCacheAdd(verdictCache, copiedPacketInfo, PORTMASTER_VERDICT_ACCEPT, &packetInfoToFree);

            // Free returned packet info.
            if (packetInfoToFree != NULL) {
                portmasterFree(packetInfoToFree);
            }

            // In case of failure, abort and free copied data.
            if (rc != 0) {
                ERR("failed to add verdict: %d", rc);
                portmasterFree(copiedPacketInfo);
                // TODO: free other allocated memory.
                return FWP_ACTION_NONE;
            }

        } else {
            // If not fast-tracked, copy the packet and register it.

            //Inbound traffic requires special treatment - this bit shifting is a special source of error ;-)
            if (packetInfo->direction == DIRECTION_INBOUND) {
                status = NdisRetreatNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
                if (!NT_SUCCESS(status)) {
                    ERR("failed to retreat net buffer data start");
                    // TODO: free other allocated memory.
                    return FWP_ACTION_NONE;
                }
            }

            // Copy the packet data.
            status = copyPacketDataFromNB(nb, 0, &data, &dataLength);
            if (!NT_SUCCESS(status)) {
                ERR("copyPacketDataFromNB 2: %d", status);
                // TODO: free other allocated memory.
                return FWP_ACTION_NONE;
            }
            copiedPacketInfo->packetSize = (UINT32)dataLength;
            INFO("copyPacketDataFromNB rc=%d, dataLength=%d", status, dataLength);

            // In order to be as clean as possible, we shift back nb, even though it may not be necessary.
            if (packetInfo->direction == DIRECTION_INBOUND) {
                NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
            }

            // Register packet.
            PortmasterPacketInfo *packetInfoToFree = NULL;
            void* dataToFree = NULL;

            DEBUG("trying to register packet");
            // Explicit lock is required, because two or more callouts can run simultaneously.
            copiedPacketInfo->id = packetCacheRegister(packetCache, copiedPacketInfo, data, dataLength, &packetInfoToFree, &dataToFree);
            INFO("registered packet with ID %u: %s", copiedPacketInfo->id, printIpv4Packet(data));

            if (packetInfoToFree != NULL && dataToFree != NULL) {
                portmasterFree(packetInfoToFree);
                portmasterFree(dataToFree);
            }
        }

        // send to queue
        /* queuedEntries = */ KeInsertQueue(globalIOQueue, &(dentry->entry));

        if (fastTracked) {
            return FWP_ACTION_PERMIT;
        }
        return FWP_ACTION_NONE;
    }
}

void classifyMultiple(
    PortmasterPacketInfo* packetInfo,
    VerdictCache *verdictCache,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    FWPS_CLASSIFY_OUT* classifyOut
    ) {

    /*
     * The classifyFn may receive multiple netbuffer lists (chained), which in turn may each have multiple netbuffers.
     *
     * Multiple netbuffer lists are possible in stream and forward layers.
     * Multiple buffers are possible for outgoing data.
     *
     * Source: https://docs.microsoft.com/en-us/windows-hardware/drivers/network/packet-indication-format
     */

    /*
     * All NET_BUFFERs in a NET_BUFFER_LIST always belong to the same flow,
     * which is identified by the five-tuple of TCP/IP (Source IP Address,
     * Destination IP Address, Source Port, Destination Port, and Protocol).
     * Source (ish): https://docs.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering
     */

    // First, run checks and get data that applies to all packets.

    // sanity check
    if (classifyOut == NULL) {
        ERR("Missing classifyOut");
        return;
    }
    if (packetInfo == NULL || verdictCache == NULL|| inMetaValues == NULL || layerData == NULL) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    // Get injection handle.
    HANDLE handle = getInjectionHandleForPacket(packetInfo);

    // Interpret layer data as netbuffer list and check if it's a looping packet.
    // Packets created/injected by us will loop back to us.
    PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST) layerData;
    FWPS_PACKET_INJECTION_STATE injectionState = FwpsQueryPacketInjectionState(handle, nbl, NULL);
    if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
        injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        classifyOut->actionType = FWP_ACTION_PERMIT;

        // We must always hard permit here, as the Windows Firewall sometimes
        // blocks our injected packets.
        // The follow-up (directly accepted) packets are not blocked.
        // Note: Hard Permit is now the default and is set immediately in the
        // callout.

        INFO("packet was in loop, injectionState= %d ", injectionState);
        return;
    }

    // Get block injection handle.
    handle = getBlockedPacketInjectHandle(packetInfo);
    injectionState = FwpsQueryPacketInjectionState(handle, nbl, NULL);
    if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
        injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        classifyOut->actionType = FWP_ACTION_PERMIT;

        // We must always hard permit here, as the Windows Firewall sometimes
        // blocks our injected packets.
        // The follow-up (directly accepted) packets are not blocked.
        // Note: Hard Permit is now the default and is set immediately in the
        // callout.

        INFO("blocked packet was in loop, injectionState= %d ", injectionState);
        return;
    }

    #ifdef DEBUG_ON
    // Print if packet is injected by someone else for debugging purposes.
    if (injectionState == FWPS_PACKET_INJECTED_BY_OTHER) {
        INFO("packet was injected by other, injectionState= %d ", injectionState);
    }
    #endif // DEBUG

    // Permit fragmented packets.
    // But of course not the first one, we are checking that one!
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FRAGMENT_DATA) &&
        inMetaValues->fragmentMetadata.fragmentOffset != 0) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        INFO("Permitting fragmented packet: %s", printPacketInfo(packetInfo));
        return;
    }

    // get header size
    UINT32 ipHeaderSize = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_IP_HEADER_SIZE)) {
        ipHeaderSize = inMetaValues->ipHeaderSize;
    } else {
        ERR("inMetaValues does not have ipHeaderSize");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }
    if (ipHeaderSize == 0) {
        ERR("inMetaValues reports an ipHeaderSize of 0");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    // Handle multiple net buffer lists and net buffers.
    // Docs say that multiple NBs can only happen for outbound data.

    // Iterate over net buffer lists.
    UINT32 nblLoopI = 0;
    UINT32 nbLoopI = 0;
    for (; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {

        // Get first netbuffer from list.
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);

        // Loop guard.
        nblLoopI++;
        DEBUG("handling NBL #%d at 0p%p", nblLoopI, nbl);
        if (nblLoopI > 100) {
            ERR("we are looooooopin! wohooooo! NOT.");
            classifyOut->actionType = FWP_ACTION_BLOCK;
            return;
        }
        nbLoopI = 0;

        // Iterate over net buffers.
        for (; nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
            FWP_ACTION_TYPE action;

            // Loop guard.
            nbLoopI++;
            DEBUG("handling NB #%d at 0p%p", nbLoopI, nb);
            if (nbLoopI > 1000) {
                ERR("we are looooooopin! wohooooo! NOT.");
                classifyOut->actionType = FWP_ACTION_BLOCK;
                return;
            }

            // Reset packetInfo.
            packetInfo->protocol = 0;
            packetInfo->localPort = 0;
            packetInfo->remotePort = 0;
            packetInfo->processID = 0;

            // Classify net buffer.
            action = classifySingle(packetInfo, verdictCache, inMetaValues, nb, ipHeaderSize);
            switch (action) {
            case FWP_ACTION_PERMIT:
                // Permit packet.

                // Special case:
                // If there is only one NBL and we already have a verdict in
                // cache for the first packet, all other NBs will have the
                // same verdict, as all packets in an NBL belong to the same
                // connection. So we can directly accept all of them at once.
                if (nblLoopI == 1 && nbLoopI == 1 && NET_BUFFER_LIST_NEXT_NBL(nbl) == NULL) {
                    #ifdef DEBUG_ON
                    for (nb = NET_BUFFER_NEXT_NB(nb); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
                        // Loop guard.
                        nbLoopI++;
                        if (nbLoopI > 1000) {
                            ERR("we are looooooopin! wohooooo! NOT.");
                            classifyOut->actionType = FWP_ACTION_BLOCK;
                            return;
                        }
                    }
                    DEBUG("permitting whole NBL with %d NBs", nbLoopI);
                    #endif // DEBUG
                    classifyOut->actionType = FWP_ACTION_PERMIT;
                    return;
                }

                // In any other case, we need to re-inject the packet, as
                // returning FWP_ACTION_PERMIT would permit all NBLs.
                copyAndInject(packetInfo, nb, ipHeaderSize);
                break;

            case FWP_ACTION_BLOCK:
                // Drop packet.

                // Special case:
                // If there is only one NBL and we already have a verdict in
                // cache for the first packet, all other NBs will have the
                // same verdict, as all packets in an NBL belong to the same
                // connection. So we can directly block all of them at once.
                if (nblLoopI == 1 && nbLoopI == 1 && NET_BUFFER_LIST_NEXT_NBL(nbl) == NULL) {
                    DEBUG("blocking whole NBL");
                    classifyOut->actionType = FWP_ACTION_BLOCK;
                    return;
                }

                // In any other case, we just do nothing to drop the packet, as
                // returning FWP_ACTION_BLOCK would block all NBLs.
                // TODO: Add ability to block packets, ie. respond with informational ICMP packet.
                break;

            case FWP_ACTION_NONE:
                // Packet has been fully handled by classifySingle.
                // This will be the case for redirects.
                // We don't need to do anything here, as we are already stealing the packet.
                break;

            default:
                // Unexpected value, drop the packet.
                classifyOut->actionType = FWP_ACTION_BLOCK;
                return;

            }
        }
    }

    // Block and absorb.
    // Source: https://docs.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB; // Set Absorb Flag
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;     // Clear Write Flag
}

void classifyInboundIPv4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {

    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyContext);


    // Sanity check 1
    if (!classifyOut) {
        ERR("Missing classifyOut");
        return;
    }

    // Use hard blocking and permitting.
    // This ensure that:
    // 1) Our blocks cannot be overruled by any other firewall.
    // 2) Our permits have a better chance of getting through the Windows Firewall.
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Hard block.

    // Sanity check 2
    if (!inFixedValues || !inMetaValues || !layerData) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    PortmasterPacketInfo inboundV4PacketInfo = {0};
    inboundV4PacketInfo.direction = DIRECTION_INBOUND;
    inboundV4PacketInfo.ipV6 = 0;
    inboundV4PacketInfo.localIP[0] = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32;
    inboundV4PacketInfo.remoteIP[0] = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32;
    inboundV4PacketInfo.interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
    inboundV4PacketInfo.subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;

    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        inboundV4PacketInfo.compartmentId = inMetaValues->compartmentId;
    } else {
        inboundV4PacketInfo.compartmentId = UNSPECIFIED_COMPARTMENT_ID;
    }

    classifyMultiple(&inboundV4PacketInfo, verdictCacheV4, inMetaValues, layerData, classifyOut);
}

void classifyOutboundIPv4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {

    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyContext);

    // Sanity check 1
    if (!classifyOut) {
        ERR("Missing classifyOut");
        return;
    }

    // Use hard blocking and permitting.
    // This ensure that:
    // 1) Our blocks cannot be overruled by any other firewall.
    // 2) Our permits have a better chance of getting through the Windows Firewall.
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Hard block.

    // Sanity check 2
    if (!inFixedValues || !inMetaValues || !layerData) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    PortmasterPacketInfo outboundV4PacketInfo = {0};
    outboundV4PacketInfo.direction = DIRECTION_OUTBOUND;
    outboundV4PacketInfo.ipV6 = 0;
    outboundV4PacketInfo.localIP[0] = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_LOCAL_ADDRESS].value.uint32;
    outboundV4PacketInfo.remoteIP[0] = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_IP_REMOTE_ADDRESS].value.uint32;
    outboundV4PacketInfo.interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
    outboundV4PacketInfo.subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;

    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        outboundV4PacketInfo.compartmentId = inMetaValues->compartmentId;
    } else {
        outboundV4PacketInfo.compartmentId = UNSPECIFIED_COMPARTMENT_ID;
    }

    classifyMultiple(&outboundV4PacketInfo, verdictCacheV4, inMetaValues, layerData, classifyOut);
}

void classifyInboundIPv6(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {

    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyContext);

    // Sanity check 1
    if (!classifyOut) {
        ERR("Missing classifyOut");
        return;
    }

    // Use hard blocking and permitting.
    // This ensure that:
    // 1) Our blocks cannot be overruled by any other firewall.
    // 2) Our permits have a better chance of getting through the Windows Firewall.
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Hard block.

    // Sanity check 2
    if (!inFixedValues || !inMetaValues || !layerData) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    PortmasterPacketInfo inboundV6PacketInfo = {0};
    inboundV6PacketInfo.direction = DIRECTION_INBOUND;
    inboundV6PacketInfo.ipV6 = 1;

    NTSTATUS status = copyIPv6(inFixedValues, FWPS_FIELD_INBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS, inboundV6PacketInfo.localIP);
    if (status != STATUS_SUCCESS) {
        ERR("Could not copy IPv6, status= 0x%x", status);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    status = copyIPv6(inFixedValues, FWPS_FIELD_INBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS, inboundV6PacketInfo.remoteIP);
    if (status != STATUS_SUCCESS) {
        ERR("Could not copy IPv6, status= 0x%x", status);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    inboundV6PacketInfo.interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32;
    inboundV6PacketInfo.subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32;

    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        inboundV6PacketInfo.compartmentId = inMetaValues->compartmentId;
    } else {
        inboundV6PacketInfo.compartmentId = UNSPECIFIED_COMPARTMENT_ID;
    }
    classifyMultiple(&inboundV6PacketInfo, verdictCacheV6, inMetaValues, layerData, classifyOut);
}

void classifyOutboundIPv6(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {

    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyContext);

    PortmasterPacketInfo outboundV6PacketInfo = {0};
    NTSTATUS status;

    // Sanity check 1
    if (!classifyOut) {
        ERR("Missing classifyOut");
        return;
    }

    // Use hard blocking and permitting.
    // This ensure that:
    // 1) Our blocks cannot be overruled by any other firewall.
    // 2) Our permits have a better chance of getting through the Windows Firewall.
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE; // Hard block.

    // Sanity check 2
    if (!inFixedValues || !inMetaValues || !layerData) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    outboundV6PacketInfo.direction = DIRECTION_OUTBOUND;
    outboundV6PacketInfo.ipV6 = 1;

    status= copyIPv6(inFixedValues, FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS, outboundV6PacketInfo.localIP);
    if (status != STATUS_SUCCESS) {
        ERR("Could not copy IPv6, status= 0x%x", status);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    status= copyIPv6(inFixedValues, FWPS_FIELD_OUTBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS, outboundV6PacketInfo.remoteIP);
    if (status != STATUS_SUCCESS) {
        ERR("Could not copy IPv6, status= 0x%x", status);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    outboundV6PacketInfo.interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32;
    outboundV6PacketInfo.subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32;

    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
        outboundV6PacketInfo.compartmentId = inMetaValues->compartmentId;
    } else {
        outboundV6PacketInfo.compartmentId = UNSPECIFIED_COMPARTMENT_ID;
    }
    classifyMultiple(&outboundV6PacketInfo, verdictCacheV6, inMetaValues, layerData, classifyOut);
}

// Used for freeing the packet info memory when clearing the packet cache
static void freePacketInfo(PortmasterPacketInfo *info, verdict_t verdict) {
    UNREFERENCED_PARAMETER(verdict);
    if(info != NULL) {
        portmasterFree(info);
    }
}

static void freePacketInfoAndData(PortmasterPacketInfo *info, void *data) {
    if(info != NULL && data != NULL) {
        portmasterFree(info);
        portmasterFree(data);
    }
}

void clearCache() {
    INFO("Cleaning all verdict cache");

    // Clear IPv4 verdict cache
    // freePacketInfo will free the packet info stored in every item of the cache
    verdictCacheClear(verdictCacheV4, freePacketInfo);

    // Clear IPv6 verdict cache
    // freePacketInfo will free the packet info stored in every item of the cache
    verdictCacheClear(verdictCacheV6, freePacketInfo);
}

void teardownCache() {
    verdictCacheTeardown(verdictCacheV4, freePacketInfo);
    verdictCacheTeardown(verdictCacheV6, freePacketInfo);

    verdictCacheV4 = NULL;
    verdictCacheV6 = NULL;

    packetCacheTeardown(packetCache, freePacketInfoAndData);
    packetCache = NULL;
}