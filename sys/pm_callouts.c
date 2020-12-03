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
#include "packet_cache.h"
#include "pm_netbuffer.h"
#define LOGGER_NAME "pm_callouts"
#include "pm_debug.h"
#include "pm_checksum.h"

#include "pm_utils.h"
#include <intsafe.h>

/******************************************************************
 * Global (static) data structures
 ******************************************************************/
static portmaster_packet_info inboundV4PacketInfo = {0};
static portmaster_packet_info outboundV4PacketInfo = {0};
static portmaster_packet_info inboundV6PacketInfo = {0};
static portmaster_packet_info outboundV6PacketInfo = {0};

static verdict_cache_t* verdictCacheV4;
static KSPIN_LOCK verdictCacheV4Lock;

static verdict_cache_t* verdictCacheV6;
static KSPIN_LOCK verdictCacheV6Lock;

packet_cache_t* packetCache;    //Not static anymore, because it is also used in pm_kernel.c
KSPIN_LOCK packetCacheLock;

static HANDLE inject_handle = NULL;
static HANDLE injectv6_handle = NULL;


/******************************************************************
 * Helper Functions
 ******************************************************************/
static void free_after_inject(VOID *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatch_level);

NTSTATUS initCalloutStructure() {
    int rc;
    NTSTATUS status;

    rc = create_verdict_cache(PM_VERDICT_CACHE_SIZE, &verdictCacheV4);
    if (rc != 0) {
        return STATUS_INTERNAL_ERROR;
    }
    KeInitializeSpinLock(&verdictCacheV4Lock);

    rc = create_verdict_cache(PM_VERDICT_CACHE_SIZE, &verdictCacheV6);
    if (rc != 0) {
        return STATUS_INTERNAL_ERROR;
    }
    KeInitializeSpinLock(&verdictCacheV6Lock);

    rc = create_packet_cache(PM_PACKET_CACHE_SIZE, &packetCache);
    if (rc != 0) {
        return STATUS_INTERNAL_ERROR;
    }
    KeInitializeSpinLock(&packetCacheLock);

    // Create the packet injection handles.
    status = FwpsInjectionHandleCreate(AF_INET,
            FWPS_INJECTION_TYPE_NETWORK,
            &inject_handle);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create WFP packet injection handle", status);
        return status;
    }

    status = FwpsInjectionHandleCreate(AF_INET6,
            FWPS_INJECTION_TYPE_NETWORK,
            &injectv6_handle);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create WFP ipv6 packet injection handle", status);
        return status;
    }

    return STATUS_SUCCESS;
}

void destroyCalloutStructure() {
    if (inject_handle != NULL) {
        FwpsInjectionHandleDestroy(inject_handle);
        inject_handle = NULL;
    }
    if (injectv6_handle != NULL) {
        FwpsInjectionHandleDestroy(injectv6_handle);
        injectv6_handle = NULL;
    }
}

NTSTATUS genericNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID * filterKey,
    const FWPS_FILTER * filter) {
    NTSTATUS status = STATUS_SUCCESS;
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
    return status;
}

NTSTATUS genericFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
    return STATUS_SUCCESS;
}

NTSTATUS copyIPv6(const FWPS_INCOMING_VALUES* inFixedValues, FWPS_FIELDS_OUTBOUND_IPPACKET_V6 idx, UINT32* ip) {
    int i;
    UINT32* ipV6;

    // sanity check
    if (!inFixedValues || !ip) {
        ERR("Invalid parameters");
        return STATUS_INVALID_PARAMETER;
    }

    // check type
    if (inFixedValues->incomingValue[idx].value.type != FWP_BYTE_ARRAY16_TYPE) {
        ERR("invalid IPv6 data type: 0x%X", inFixedValues->incomingValue[idx].value.type);
        ip[0] = ip[1] = ip[2] = ip[3] = 0;
        return STATUS_INVALID_PARAMETER;
    }

    // copy and swap
    ipV6 = (UINT32*) inFixedValues->incomingValue[idx].value.byteArray16->byteArray16;
    for (i = 0; i < 4; i++) {
        ip[i]= RtlUlongByteSwap(ipV6[i]);
    }

    return STATUS_SUCCESS;
}

void redir_from_callout(FWPS_CLASSIFY_OUT* classifyOut, pportmaster_packet_info packetInfo, pportmaster_packet_info redirInfo, PNET_BUFFER nb, size_t ipHeaderSize, BOOL dns) {
    void* packet;
    ULONG packet_len;
    NTSTATUS status;

    // sanity check
    if (!redirInfo) {
        ERR("redirInfo is NULL!");
    }
    if (!classifyOut || !packetInfo || !redirInfo || !nb || ipHeaderSize == 0) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    // DEBUG: print its TCP 4-tuple
    INFO("Handling redir for %s", print_packet_info(packetInfo));

    //Block, Absorb, and Copy Packet to packet_cashe
    //according to https://docs.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->flags|= FWPS_CLASSIFY_OUT_FLAG_ABSORB;   //Set Absorb Bit 1
    classifyOut->rights&= ~FWPS_RIGHT_ACTION_WRITE;     //Set Write Bit 0

    //Inbound traffic requires special treatment - dafuq?
    if (packetInfo->direction == 1) {   //Inbound
        status = NdisRetreatNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
        if (!NT_SUCCESS(status)) {
            ERR("BBBBBBB!!!!");
            return;
        }
    }

    //Create new Packet -> wrap it in new nb, so we don't need to shift this nb back.
    status = copy_packet_data_from_nb(nb, 0, &packet, &packet_len);
    if (!NT_SUCCESS(status)) {
        ERR("AAAA!!! copy_packet_data_from_nb 3: %d", status);
        return;
    }
    //Now data should contain a full blown packet

    //In order to be as clean as possible, we shift back nb, even though it may not be necessary
    if (packetInfo->direction == 1) {   //Inbound
        NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
    }
    redir(packetInfo, redirInfo, packet, packet_len, dns);

}

void redir(pportmaster_packet_info packetInfo, pportmaster_packet_info redirInfo, void* packet, ULONG packet_len, BOOL dns) {
    PNET_BUFFER_LIST nbl;
    HANDLE handle= NULL;
    NTSTATUS status;

    // sanity check
    if (!packetInfo || !redirInfo || !packet || packet_len == 0) {
        ERR("Invalid parameters");
        return;
    }

    INFO("About to modify headers for %s", print_packet_info(packetInfo));
    INFO("Packet starts at 0p%p with %u bytes", packet, packet_len);

    // Modifiy headers
    if (packetInfo->ipV6 == 0) { // IPv4
        ULONG ip_header_len = calc_ipv4_header_size(packet, packet_len);
        if (ip_header_len > 0) { // IPv4 Header
            PIPV4_HEADER ip_header = (PIPV4_HEADER) packet;

            if (packetInfo->direction == 0) { // Outbound
                ip_header->DstAddr = RtlUlongByteSwap(packetInfo->localIP[0]);
                // IP_LOCALHOST is rejected by Windows Networkstack (nbl-status 0xc0000207, "STATUS_INVALID_ADDRESS_COMPONENT"
                // Problem might be switching Network scope from "eth0" to "lo"
                // Instead, just redir to the address the packet came from
            } else {
                ip_header->SrcAddr = RtlUlongByteSwap(redirInfo->remoteIP[0]);
            }

            // TCP
            if (ip_header->Protocol == 6 && packet_len >= ip_header_len + 20 /* TCP Header */) {
                PTCP_HEADER tcp_header = (PTCP_HEADER) ((UINT8*)packet + ip_header_len);

                if (packetInfo->direction == 0) {
                    if (dns) {
                        tcp_header->DstPort= PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        tcp_header->DstPort= PORT_G17EP_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    tcp_header->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

                // UDP
            } else if (ip_header->Protocol == 17 && packet_len >= ip_header_len + 8 /* UDP Header */) {
                PUDP_HEADER udp_header = (PUDP_HEADER) ((UINT8*)packet + ip_header_len);

                if (packetInfo->direction == 0) {
                    if (dns) {
                        udp_header->DstPort= PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        udp_header->DstPort= PORT_G17EP_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    udp_header->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

            } else {  //Neither UDP nor TCP -> We can only redirect UDP or TCP -> drop the rest
                portmaster_free(packet);
                WARN("Portmaster issued redirect for Non UDP or TCP Packet:");
                WARN("%s", print_packet_info(packetInfo));
                return;
            }
        } else { // not enough data for IPv4 Header
            portmaster_free(packet);
            WARN("IPv4 Packet too small:");
            WARN("%s", print_packet_info(packetInfo));
            return;
        }
    } else { // IPv6
        ULONG ip_header_len = calc_ipv6_header_size(packet, packet_len, NULL);
        if (ip_header_len > 0) { // IPv6 Header
            PIPV6_HEADER ip_header = (PIPV6_HEADER) packet;
            int i;

            if (packetInfo->direction == 0) { // Outbound
                for (i = 0; i < 4; i++) {
                    ip_header->DstAddr[i]= RtlUlongByteSwap(packetInfo->localIP[i]);
                }
                // IP_LOCALHOST is rejected by Windows Networkstack (nbl-status 0xc0000207, "STATUS_INVALID_ADDRESS_COMPONENT"
                // Problem might be switching Network scope from "eth0" to "lo"
                // Instead, just redir to the address the packet came from
            } else {
                for (i = 0; i < 4; i++) {
                    ip_header->SrcAddr[i]= RtlUlongByteSwap(redirInfo->remoteIP[i]);
                }
            }

            // TCP
            if (ip_header->NextHdr == 6 && packet_len >= ip_header_len + 20 /* TCP Header */) {
                PTCP_HEADER tcp_header = (PTCP_HEADER) ((UINT8*)packet + ip_header_len);

                if (packetInfo->direction == 0) {
                    if (dns) {
                        tcp_header->DstPort= PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        tcp_header->DstPort= PORT_G17EP_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    tcp_header->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

                // UDP
            } else if (ip_header->NextHdr == 17 && packet_len >= ip_header_len + 8 /* UDP Header */) {
                PUDP_HEADER udp_header = (PUDP_HEADER) ((UINT8*)packet + ip_header_len);

                if (packetInfo->direction == 0) {
                    if (dns) {
                        udp_header->DstPort= PORT_DNS_NBO; // Port 53 in Network Byte Order!
                    } else {
                        udp_header->DstPort= PORT_G17EP_NBO; // Port 717 in Network Byte Order!
                    }
                } else {
                    udp_header->SrcPort= RtlUshortByteSwap(redirInfo->remotePort);
                }

            } else {  //Neither UDP nor TCP -> We can only redirect UDP or TCP -> drop the rest
                portmaster_free(packet);
                WARN("Portmaster issued redirect for Non UDP or TCP Packet:");
                WARN("%s", print_packet_info(packetInfo));
                return;
            }
        } else { // not enough data for IPv6 Header
            portmaster_free(packet);
            WARN("IPv6 Packet too small:");
            WARN("%s", print_packet_info(packetInfo));
            return;
        }
    }
    INFO("Headers modified");

    // fix checksums
    if (!packetInfo->ipV6) {
        calc_ipv4_checksum(packet, packet_len, TRUE);
    } else {
        calc_ipv6_checksum(packet, packet_len, TRUE);
    }

    // re-inject ...
    status = wrap_packet_data_in_nb(packet, packet_len, &nbl);
    if (!NT_SUCCESS(status)) {
        ERR("AAAA!!! wrap_packet_data_in_nb failed: %u", status);
        portmaster_free(packet);
        return;
    }

    if (packetInfo->ipV6 == 0) {
        handle= inject_handle;
    } else {
        handle= injectv6_handle;
    }

    // Reset routing compartment ID, as we are changing where this is going to.
    // This necessity is unconfirmed.
    packetInfo->compartmentId = UNSPECIFIED_COMPARTMENT_ID;

    if (packetInfo->direction == 0) {
        INFO("Send: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), print_ipv4_packet(packet));
        status = FwpsInjectNetworkSendAsync(handle, NULL, 0,
                packetInfo->compartmentId, nbl, free_after_inject,
                packet);
        INFO("InjectNetworkSend executed: %s", print_packet_info(packetInfo));
    } else {
        INFO("Rcv: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), print_ipv4_packet(packet));
        status = FwpsInjectNetworkReceiveAsync(handle, NULL, 0,
                packetInfo->compartmentId, packetInfo->interfaceIndex,
                packetInfo->subInterfaceIndex, nbl, free_after_inject,
                packet);
        INFO("InjectNetworkReceive executed: %s", print_packet_info(packetInfo));
    }

    if (!NT_SUCCESS(status)) {
        ERR("FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
        free_after_inject(packet, nbl, FALSE);
    }

    return;
}

static void free_after_inject(VOID *context, NET_BUFFER_LIST *nbl, BOOLEAN dispatch_level) {
    PMDL mdl;
    PNET_BUFFER nb;
    UNREFERENCED_PARAMETER(dispatch_level);

    // sanity check
    if (!nbl) {
        ERR("Invalid parameters");
        return;
    }

    INFO("free_after_inject: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), print_ipv4_packet(context));
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    mdl = NET_BUFFER_FIRST_MDL(nb);
    IoFreeMdl(mdl);
    FwpsFreeNetBufferList(nbl);

    if (context != NULL) {  //context is packet
        portmaster_free(context);
    }
}

void respondWithVerdict(UINT32 id, verdict_t verdict) {
    pportmaster_packet_info packetInfo;
    void* packet;
    size_t packet_len;
    PNET_BUFFER_LIST nbl;
    NTSTATUS status;
    KLOCK_QUEUE_HANDLE lock_handle;
    HANDLE handle;
    int rc;
    BOOL temporary = FALSE;

    // sanity check
    if (id == 0 || verdict == 0) {
        ERR("Invalid parameters");
        return;
    }

    if (verdict < 0) {
        temporary = TRUE;
        verdict = verdict * -1;
    }

    INFO("Trying to retrieve packet");
    KeAcquireInStackQueuedSpinLock(&packetCacheLock, &lock_handle);
    rc = retrieve_packet(packetCache, id, &packetInfo, &packet, &packet_len);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    if (rc != 0) {
        // packet id was not in packet cache
        INFO("reveiced verdict response for unknown packet id: %u", id);
        return;
    }
    INFO("received verdict responst for packet id: %u", id);

    //Store permanent verdicts in verdictCache
    if (!temporary) {
        if (packetInfo->ipV6 == 0) {
            KeAcquireInStackQueuedSpinLock(&verdictCacheV4Lock, &lock_handle);
            rc = add_verdict(verdictCacheV4, packetInfo, verdict);
            KeReleaseInStackQueuedSpinLock(&lock_handle);
        } else {
            KeAcquireInStackQueuedSpinLock(&verdictCacheV6Lock, &lock_handle);
            rc = add_verdict(verdictCacheV6, packetInfo, verdict);
            KeReleaseInStackQueuedSpinLock(&lock_handle);
        }
    }

    //If verdict could not be added, drop and free the packet
    if (rc != 0) {
        portmaster_free(packetInfo);
        portmaster_free(packet);
        return;
    }

    //Handle Packet according to Verdict
    switch (verdict) {
        case PORTMASTER_VERDICT_DROP:
            INFO("PORTMASTER_VERDICT_DROP: %s", print_packet_info(packetInfo));
            portmaster_free(packet);
            return;
        case PORTMASTER_VERDICT_BLOCK:
            // TODO: respond with block
            INFO("PORTMASTER_VERDICT_BLOCK: %s", print_packet_info(packetInfo));
            portmaster_free(packet);
            return;
        case PORTMASTER_VERDICT_ACCEPT:
            DEBUG("PORTMASTER_VERDICT_ACCEPT: %s", print_packet_info(packetInfo));
            break;
        case PORTMASTER_VERDICT_REDIR_DNS:
            INFO("PORTMASTER_VERDICT_REDIR_DNS: %s", print_packet_info(packetInfo));
            redir(packetInfo, packetInfo, packet, packet_len, TRUE);
            return;
        case PORTMASTER_VERDICT_REDIR_TUNNEL:
            INFO("PORTMASTER_VERDICT_REDIR_TUNNEL: %s", print_packet_info(packetInfo));
            redir(packetInfo, packetInfo, packet, packet_len, FALSE);
            return;
        default:
            WARN("unknown verdict: 0x%x {%s}", print_packet_info(packetInfo));
            portmaster_free(packet);
            return;
    }

    // fix checksums (IPv6 does not have an IP checksum that we would have to fix)
    if (!packetInfo->ipV6) {
        calc_ipv4_checksum(packet, packet_len, FALSE);
    }

    // re-inject ...
    status = wrap_packet_data_in_nb(packet, packet_len, &nbl);
    if (!NT_SUCCESS(status)) {
        ERR("AAAA!!! wrap_packet_data_in_nb failed: %u", status);
        portmaster_free(packet);
        if (temporary) {
            portmaster_free(packetInfo);
        }
        return;
    }

    if (packetInfo->ipV6 == 0) {
        handle= inject_handle;
    } else {
        handle= injectv6_handle;
    }

    if (packetInfo->direction == 0) {
        INFO("Send: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), print_ipv4_packet(packet));
        status = FwpsInjectNetworkSendAsync(handle, NULL, 0,
                packetInfo->compartmentId, nbl, free_after_inject,
                packet);
        INFO("InjectNetworkSend executed: %s", print_packet_info(packetInfo));
    } else {
        INFO("Rcv: nbl_status=0x%x, %s", NET_BUFFER_LIST_STATUS(nbl), print_ipv4_packet(packet));
        INFO("INJECTING packet id %u", packetInfo->id);
        status = FwpsInjectNetworkReceiveAsync(handle, NULL, 0,
                packetInfo->compartmentId, packetInfo->interfaceIndex,
                packetInfo->subInterfaceIndex, nbl, free_after_inject,
                packet);
        INFO("InjectNetworkReceive executed: %s", print_packet_info(packetInfo));
    }

    if (!NT_SUCCESS(status)) {
        ERR("FwpsInjectNetworkSendAsync or FwpsInjectNetworkReceiveAsync returned %d", status);
        //free_after_inject(packet, nbl, FALSE);
    }

    // If verdict is temporary, free packetInfo
    if (temporary) {
        portmaster_free(packetInfo);
    }
    // otherwise leaf packetInfo because it is referenced by verdict_cache

    INFO("Good Bye respondWithVerdict");
    return;
}

//Checks if packet is in Loop
//Return values:
//  true: packet was handled before -> let it flow (FWP_ACTION_PERMIT)
//  false: handle packet now
BOOL packet_in_loop(HANDLE handle, PNET_BUFFER_LIST nbl, FWPS_CLASSIFY_OUT* classifyOut) {

    // sanity check
    if (!classifyOut || !nbl) {
        ERR("Invalid parameters");
        return FALSE;
    }

    if (handle != NULL) {
        FWPS_PACKET_INJECTION_STATE injection_state = FwpsQueryPacketInjectionState(handle, nbl, NULL);
        if (injection_state == FWPS_PACKET_INJECTED_BY_SELF ||
            injection_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
            //SetEvent(wfp->Event);
            INFO("packet was in loop, injection_state= %d ", injection_state);
            return TRUE;
        }
    }

    return FALSE;
}


/******************************************************************
 * Classify Functions
 ******************************************************************/
void classifyAll(portmaster_packet_info* packetInfo,
    verdict_cache_t* verdictCache,
    KSPIN_LOCK* verdictCacheLock,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    FWPS_CLASSIFY_OUT* classifyOut) {
    int offset;
    verdict_t verdict;
    int rc;
    PDATA_ENTRY dentry;
    KLOCK_QUEUE_HANDLE lock_handle_vc, lock_handle_pc;
    pportmaster_packet_info copiedPacketInfo, redirInfo;
    PPM_IPHDR ip_header;
    PNET_BUFFER_LIST nbl;
    PNET_BUFFER nb;
    UINT32 ipHeaderSize;
    UINT16 srcPort, dstPort;
    ULONG maxBytes, data_len;
    NTSTATUS status;
    void* data;
    BOOL copiedNBForPacketInfo= FALSE;
    HANDLE handle;

    // sanity check
    if (!packetInfo || !verdictCache || !verdictCacheLock || !inMetaValues || !layerData || !classifyOut) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    // If we don't get the right to write, block the packet.
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        ERR("No right to write -> block: %s", print_packet_info(packetInfo));
        return;
    }

    // Get injection handle.
    if (packetInfo->ipV6) {
        handle = injectv6_handle;
    } else {
        handle = inject_handle;
    }

    // Interpret layer data as netbuffer list and check if it's a looping packet.
    // Packets created/injected by us will loop back to us.
    nbl = (PNET_BUFFER_LIST) layerData;
    if (packet_in_loop(handle, nbl, classifyOut)) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        INFO("packet was in loop");
        return;
    }

    // get header size
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_IP_HEADER_SIZE)) {
        ipHeaderSize = inMetaValues->ipHeaderSize;
    } else {
        ERR("AAAAAA!!!!");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }
    if (ipHeaderSize == 0) {
        ERR("inMetaValues reports an ipHeaderSize of 0");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    // Get first netbuffer from list.
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    //Inbound traffic requires special treatment - dafuq?
    if (packetInfo->direction == 1) { //Inbound
        status = NdisRetreatNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
        if (!NT_SUCCESS(status)) {
            ERR("AAAAAA!!!!");
            classifyOut->actionType = FWP_ACTION_BLOCK;
            return;
        }
    }

#ifdef DEBUG_ON
    status = borrow_packet_data_from_nb(nb, ipHeaderSize, &data);
    if (NT_SUCCESS(status)) {
        PPM_IPHDR p = (PPM_IPHDR) data;
        DEBUG("[v6=%d, dir=%d] V=%d, HL=%d, TOS=%d, TL=%d, ID=%d, FRAGO=%d, TTL=%d, P=%d, SUM=%d, SRC=%d.%d.%d.%d, DST=%d.%d.%d.%d",
            packetInfo->ipV6,
            packetInfo->direction,
            p->Version, p->HdrLength, p->TOS,
            RtlUshortByteSwap(p->Length),
            RtlUshortByteSwap(p->Id),
            RtlUshortByteSwap(p->FragOff),
            p->TTL, p->Protocol,
            RtlUshortByteSwap(p->Checksum),
            FORMAT_ADDR(RtlUlongByteSwap(p->SrcAddr)),
            FORMAT_ADDR(RtlUlongByteSwap(p->DstAddr)));
    }
#endif // DEBUG

    status = borrow_packet_data_from_nb(nb, ipHeaderSize + 4, &data);
    if (!NT_SUCCESS(status)) {
        ULONG req_bytes= ipHeaderSize + 4;
        INFO("borrow_packet_data_from_nb could not return IPHeader+4B, status=0x%X -> copy_packet_data_from_nb", status);
        // TODO: if we start to use copy_packet_data_from_nb here, free space afterwards!
        status = copy_packet_data_from_nb(nb, req_bytes, &data, &data_len);
        if (!NT_SUCCESS(status)) {
            ERR("copy_packet_data_from_nb could not copy IP Header+4 bytes, status=x%X, BLOCK", status);
            classifyOut->actionType = FWP_ACTION_BLOCK;
            return;
        }

        // check if we got enough data
        if (data_len < req_bytes) {
            if (data_len >= 10) {
                if (packetInfo->ipV6) {
                    packetInfo->protocol = ((UINT8*)data)[6];
                } else {
                    packetInfo->protocol = ((UINT8*)data)[9];
                }
            }
            ERR("Requested %u bytes, but received %u bytes (ipV6=%i, protocol=%u, status=0x%X)", req_bytes, data_len, packetInfo->ipV6, packetInfo->protocol, status);
            classifyOut->actionType = FWP_ACTION_BLOCK;
            return;
        }

        copiedNBForPacketInfo = TRUE;
    }

    // get protocol
    if (packetInfo->ipV6) {
        packetInfo->protocol = ((UINT8*) data)[6];
    } else {
        packetInfo->protocol = ((UINT8*) data)[9];
    }

    // get ports
    switch (packetInfo->protocol) {
        case 6: // TCP
        case 17: // UDP
        case 33: // DCCP
        case 136: // UDP Lite
            RtlCopyBytes((void*) &srcPort, (void*) ((UINT8*)data+ipHeaderSize), 2);
            srcPort= RtlUshortByteSwap(srcPort);
            RtlCopyBytes((void*) &dstPort, (void*) ((UINT8*)data+ipHeaderSize+2), 2);
            dstPort= RtlUshortByteSwap(dstPort);
            if (packetInfo->direction == 1) { //Inbound
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
        portmaster_free(data);
    }

    //Shift back
    if (packetInfo->direction == 1) { //Inbound
        NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
    }

    // check verdict cache
    KeAcquireInStackQueuedSpinLock(verdictCacheLock, &lock_handle_vc);
    // First check if the packet is a DNAT response
    if (packetInfo->remotePort == PORT_G17EP || packetInfo->remotePort == PORT_DNS) {
        verdict = check_reverse_redir(verdictCache, packetInfo, &redirInfo);
    }
    // Check verdict normally if we did not detect a packet that should be reverse DNAT-ed
    if (!(verdict == PORTMASTER_VERDICT_REDIR_DNS || verdict == PORTMASTER_VERDICT_REDIR_TUNNEL)) {
        verdict = check_verdict(verdictCache, packetInfo);
        // If packet should be DNAT-ed set redirInfo to packetInfo
        if (verdict == PORTMASTER_VERDICT_REDIR_DNS || verdict == PORTMASTER_VERDICT_REDIR_TUNNEL) {
            redirInfo = packetInfo;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle_vc);

    if (verdict != PORTMASTER_VERDICT_GET) { // we already have a verdict!

        switch (verdict) {
            case PORTMASTER_VERDICT_DROP:
                classifyOut->actionType = FWP_ACTION_BLOCK;
                INFO("PORTMASTER_VERDICT_DROP: %s", print_packet_info(packetInfo));
                return;
            case PORTMASTER_VERDICT_BLOCK:
                classifyOut->actionType = FWP_ACTION_BLOCK;
                INFO("PORTMASTER_VERDICT_BLOCK: %s", print_packet_info(packetInfo));
                return;
            case PORTMASTER_VERDICT_ACCEPT:
                classifyOut->actionType = FWP_ACTION_PERMIT; // we need to call FWP_ACTION_PERMIT because we use option TERMINATE, alternative would be FWP_ACTION_NONE
                DEBUG("PORTMASTER_VERDICT_ACCEPT: %s", print_packet_info(packetInfo));
                return;
            case PORTMASTER_VERDICT_REDIR_DNS:
                INFO("PORTMASTER_VERDICT_REDIR_DNS: %s", print_packet_info(packetInfo));
                redir_from_callout(classifyOut, packetInfo, redirInfo, nb, ipHeaderSize, TRUE);
                return;
            case PORTMASTER_VERDICT_REDIR_TUNNEL:
                INFO("PORTMASTER_VERDICT_REDIR_TUNNEL: %s", print_packet_info(packetInfo));
                redir_from_callout(classifyOut, packetInfo, redirInfo, nb, ipHeaderSize, FALSE);
                return;
            case PORTMASTER_VERDICT_GET:
                classifyOut->actionType = FWP_ACTION_BLOCK; // we need to call FWP_ACTION_PERMIT because we use option TERMINATE, alternative would be FWP_ACTION_NONE
                ERR("PORTMASTER_VERDICT_GET: %s", print_packet_info(packetInfo));
                return;
            default:
                WARN("unknown verdict: 0x%x {%s}", print_packet_info(packetInfo));
                classifyOut->actionType = FWP_ACTION_BLOCK;
                return;
        }

    } else { //Request Verdict from Userland
        PDATA_ENTRY dentry;
        pportmaster_packet_info copied_packet_info;
        UINT32 id;
        //char buf[256];
        int rc;

        // get process ID
        if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
            packetInfo->processID = inMetaValues->processId;
        } else {
            packetInfo->processID = 0;
        }

        // DEBUG: print its TCP 4-tuple
        INFO("Getting verdict for %s", print_packet_info(packetInfo));

        //Block, Absorb, and Copy Packet to packet_cashe
        //according to https://docs.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->flags|= FWPS_CLASSIFY_OUT_FLAG_ABSORB;   //Set Absorb Bit 1
        classifyOut->rights&= ~FWPS_RIGHT_ACTION_WRITE;       //Set Write Bit 0

        //Inbound traffic requires special treatment - this bitshifterei is a special source of error ;-)
        if (packetInfo->direction == 1) { //Inbound
            status = NdisRetreatNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
            if (!NT_SUCCESS(status)) {
                ERR("Argh!!!!");
                return;
            }
        }

        status = copy_packet_data_from_nb(nb, 0, &data, &data_len);
        if (!NT_SUCCESS(status)) {
            ERR("AAAA!!! copy_packet_data_from_nb 2: %d", status);
            return;
        }

        INFO("copy_packet_data_from_nb rc=%d, data_len=%d", status, data_len);

        //Even though nb is not used anymore (?) we still shift back (because we have a problem, which we do not understand)
        if (packetInfo->direction == 1) { //Inbound
            NdisAdvanceNetBufferDataStart(nb, ipHeaderSize, 0, NULL);
        }

        // allocate queue entry and copy packetInfo
        dentry= portmaster_malloc(sizeof(DATA_ENTRY), FALSE);
        if (!dentry) {
            ERR("Insufficient Resources for mallocating dentry");
            return;
        }
        copied_packet_info = portmaster_malloc(sizeof(portmaster_packet_info), FALSE);
        if (!copied_packet_info) {
            ERR("Insufficient Resources for mallocating copied_packet_info");
            return;
        }


        RtlCopyMemory(copied_packet_info, packetInfo, sizeof(portmaster_packet_info));
        copied_packet_info->packetSize = data_len;
        dentry->ppacket = copied_packet_info;

        //Register Packet
        //INFO("packetInfo->compartmentId= %d, ->interfaceIndex= %d, ->subInterfaceIndex= %d", packetInfo->compartmentId, packetInfo->interfaceIndex, packetInfo->subInterfaceIndex);
        DEBUG("trying to register packet");
        KeAcquireInStackQueuedSpinLock(&packetCacheLock, &lock_handle_pc);      
        //Lock packet cache because "register_packet" and "clean_packet_cache" must never run simultaniously
        //Explicit lock is required, because two or more callouts can run simultaniously 
        //btw: Never use static variables in callouts ...
        copied_packet_info->id = register_packet(packetCache, copied_packet_info, data, data_len);
        KeReleaseInStackQueuedSpinLock(&lock_handle_pc);
        INFO("registered packet with ID %u", copied_packet_info->id);

        // send to queue
        /* queuedEntries = */ KeInsertQueue(global_io_queue, &(dentry->entry));

        // attempt to clean packet cache
        {
            pportmaster_packet_info packet_info_to_free;
            void* data_to_free;
            KeAcquireInStackQueuedSpinLock(&packetCacheLock, &lock_handle_pc);
            rc = clean_packet_cache(packetCache, &packet_info_to_free, &data_to_free);
            KeReleaseInStackQueuedSpinLock(&lock_handle_pc);
            if (rc == 0) {
                portmaster_free(packet_info_to_free);
                portmaster_free(data_to_free);
            }
        }

        return;
    }
}

void classifyInboundIPv4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {

    // sanity check
    if (!inFixedValues || !inMetaValues || !layerData || !classifyOut) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    inboundV4PacketInfo.direction = 1;
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

    classifyAll(&inboundV4PacketInfo, verdictCacheV4, &verdictCacheV4Lock, inMetaValues, layerData, classifyOut);

    return;
}

void classifyOutboundIPv4(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {

    // sanity check
    if (!inFixedValues || !inMetaValues || !layerData || !classifyOut) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    outboundV4PacketInfo.direction = 0;
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

    classifyAll(&outboundV4PacketInfo, verdictCacheV4, &verdictCacheV4Lock, inMetaValues, layerData, classifyOut);

    return;
}

void classifyInboundIPv6(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {
    NTSTATUS status;

    // sanity check
    if (!inFixedValues || !inMetaValues || !layerData || !classifyOut) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    inboundV6PacketInfo.direction = 1;
    inboundV6PacketInfo.ipV6 = 1;

    status= copyIPv6(inFixedValues, FWPS_FIELD_INBOUND_IPPACKET_V6_IP_LOCAL_ADDRESS, inboundV6PacketInfo.localIP);
    if (status != STATUS_SUCCESS) {
        ERR("Could not copy IPv6, status= 0x%x", status);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    status= copyIPv6(inFixedValues, FWPS_FIELD_INBOUND_IPPACKET_V6_IP_REMOTE_ADDRESS, inboundV6PacketInfo.remoteIP);
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
    classifyAll(&inboundV6PacketInfo, verdictCacheV6, &verdictCacheV6Lock, inMetaValues, layerData, classifyOut);
    return;
}

void classifyOutboundIPv6(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    void* classifyContext,
    const FWPS_FILTER* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut) {
    NTSTATUS status;

    // sanity check
    if (!inFixedValues || !inMetaValues || !layerData || !classifyOut) {
        ERR("Invalid parameters");
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }

    outboundV6PacketInfo.direction = 0;
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
    classifyAll(&outboundV6PacketInfo, verdictCacheV6, &verdictCacheV6Lock, inMetaValues, layerData, classifyOut);
    return;
}
