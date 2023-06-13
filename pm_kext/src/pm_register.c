/*
 *  Name:        pm_register.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation for rgistering filters and
 *               callouts for the kernel using the mechanisms supplied by
 *               Windows Filtering Platform
 *
 *  Scope:       Kernelmode
 */

#include "pm_register.h"
#define LOGGER_NAME "pm_register"
#include "pm_debug.h"


// Sublayer name and ID
#define PORTMASTER_SUBLAYER_NAME        L"PortmasterSublayer"
#define PORTMASTER_SUBLAYER_DESCRIPTION L"The Portmaster sublayer holds all it's filters."
DEFINE_GUID(PORTMASTER_SUBLAYER_GUID, 0xa87fb472, 0xfc68, 0x4805, 0x85, 0x59, 0xc6, 0xae, 0x77, 0x47, 0x73, 0xe0); // a87fb472-fc68-4805-8559-c6ae774773e0

// Filter Names
#define INBOUND_V4_FILTER_NAME         L"PortmasterInboundV4Filter"
#define INBOUND_V4_FILTER_DESCRIPTION  L"This filter is used by the Portmaster to intercept inbound IPv4 traffic."
#define OUTBOUND_V4_FILTER_NAME        L"PortmasterOutboundV4Filter"
#define OUTBOUND_V4_FILTER_DESCRIPTION L"This filter is used by the Portmaster to intercept outbound IPv4 traffic."
#define INBOUND_V6_FILTER_NAME         L"PortmasterInboundV6Filter"
#define INBOUND_V6_FILTER_DESCRIPTION  L"This filter is used by the Portmaster to intercept inbound IPv6 traffic."
#define OUTBOUND_V6_FILTER_NAME        L"PortmasterOutboundV6Filter"
#define OUTBOUND_V6_FILTER_DESCRIPTION L"This filter is used by the Portmaster to intercept outbound IPv6 traffic."

#define ALE_INBOUND_V4_FILTER_NAME         L"PortmasterALEInboundV4Filter"
#define ALE_INBOUND_V4_FILTER_DESCRIPTION  L"This filter is used by the Portmaster to monitor inbound IPv4 traffic before the connection is established."
#define ALE_OUTBOUND_V4_FILTER_NAME         L"PortmasterALEOutboundV4Filter"
#define ALE_OUTBOUND_V4_FILTER_DESCRIPTION  L"This filter is used by the Portmaster to monitor outbound IPv4 traffic before the connection is established."
#define ALE_INBOUND_V6_FILTER_NAME         L"PortmasterALEInboundV6Filter"
#define ALE_INBOUND_V6_FILTER_DESCRIPTION  L"This filter is used by the Portmaster to monitor inbound IPv6 traffic before the connection is established."
#define ALE_OUTBOUND_V6_FILTER_NAME         L"PortmasterALEOutboundV6Filter"
#define ALE_OUTBOUND_V6_FILTER_DESCRIPTION  L"This filter is used by the Portmaster to monitor outbound IPv6 traffic before the connection is established."

// Callout Names
#define INBOUND_V4_CALLOUT_NAME         L"PortmasterInboundV4Callout"
#define INBOUND_V4_CALLOUT_DESCRIPTION  L"This callout is used by the Portmaster to intercept inbound IPv4 traffic."
#define OUTBOUND_V4_CALLOUT_NAME        L"PortmasterOutboundV4Callout"
#define OUTBOUND_V4_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to intercept outbound IPv4 traffic."
#define INBOUND_V6_CALLOUT_NAME         L"PortmasterInboundV6Callout"
#define INBOUND_V6_CALLOUT_DESCRIPTION  L"This callout is used by the Portmaster to intercept inbound IPv6 traffic."
#define OUTBOUND_V6_CALLOUT_NAME        L"PortmasterOutboundV6Callout"
#define OUTBOUND_V6_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to intercept outbound IPv6 traffic."

#define ALE_INBOUND_V4_CALLOUT_NAME        L"PortmasterALEInboundV4Callout"
#define ALE_INBOUND_V4_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to monitor outbound IPv4 traffic before the connection is established."
#define ALE_OUTBOUND_V4_CALLOUT_NAME        L"PortmasterALEOutboundV4Callout"
#define ALE_OUTBOUND_V4_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to montiror outbound IPv4 traffic before the connection is established."
#define ALE_INBOUND_V6_CALLOUT_NAME        L"PortmasterALEInboundV6Callout"
#define ALE_INBOUND_V6_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to monitor outbound IPv6 traffic before the connection is established."
#define ALE_OUTBOUND_V6_CALLOUT_NAME        L"PortmasterALEOutboundV6Callout"
#define ALE_OUTBOUND_V6_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to monitor outbound IPv6 traffic before the connection is established."

// GUIDs
DEFINE_GUID(INBOUND_V4_CALLOUT_GUID,  0x05c55149, 0x4732, 0x4857, 0x8d, 0x10, 0xf1, 0x78, 0xf3, 0xa0, 0x6f, 0x8c); // 05c55149-4732-4857-8d10-f178f3a06f8c
DEFINE_GUID(OUTBOUND_V4_CALLOUT_GUID, 0x41162b9e, 0x8473, 0x4b88, 0xa5, 0xeb, 0x04, 0xcf, 0x1d, 0x27, 0x6b, 0x06); // 41162b9e-8473-4b88-a5eb-04cf1d276b06
DEFINE_GUID(INBOUND_V6_CALLOUT_GUID,  0xceff1df7, 0x2baa, 0x44c5, 0xa6, 0xe5, 0x73, 0xa9, 0x58, 0x49, 0xbc, 0xff); // ceff1df7-2baa-44c5-a6e5-73a95849bcff
DEFINE_GUID(OUTBOUND_V6_CALLOUT_GUID, 0x32bad112, 0x6af4, 0x4109, 0x80, 0x9b, 0xc0, 0x75, 0x70, 0xba, 0x01, 0xb4); // 32bad112-6af4-4109-809b-c07570ba01b4

DEFINE_GUID(ALE_INBOUND_V4_CALLOUT_GUID,  0xe36216c5, 0x7b33, 0x40ee, 0xb0, 0x54, 0xfb, 0x1b, 0xc7, 0xde, 0xcc, 0x19); // e36216c5-7b33-40ee-b054-fb1bc7decc19
DEFINE_GUID(ALE_OUTBOUND_V4_CALLOUT_GUID, 0x029819fe, 0x97d9, 0x4e5f, 0xa0, 0xfb, 0x78, 0xef, 0x5c, 0xef, 0x8a, 0xc4); // 029819fe-97d9-4e5f-a0fb-78ef5cef8ac4
DEFINE_GUID(ALE_INBOUND_V6_CALLOUT_GUID,  0x77ea9927, 0x66e7, 0x4cf8, 0x9e, 0xa2, 0x94, 0x1e, 0xdf, 0x2f, 0xae, 0x63); // 77ea9927-66e7-4cf8-9ea2-941edf2fae63
DEFINE_GUID(ALE_OUTBOUND_V6_CALLOUT_GUID, 0xd6b0213a, 0x337a, 0x4cc6, 0x84, 0xc0, 0xcc, 0x60, 0x73, 0x1b, 0x9e, 0x2a); // d6b0213a-337a-4cc6-84c0-cc60731b9e2a
extern HANDLE filterEngineHandle;

// Assigned filter IDs by engine
UINT64 inboundV4FilterID;
UINT64 outboundV4FilterID;
UINT64 inboundV6FilterID;
UINT64 outboundV6FilterID;

UINT64 aleInboundV4FilterID;
UINT64 aleOutboundV4FilterID;
UINT64 aleInboundV6FilterID;
UINT64 aleOutboundV6FilterID;

// Assigned callout IDs by engine
UINT32 inboundV4CalloutID;
UINT32 outboundV4CalloutID;
UINT32 inboundV6CalloutID;
UINT32 outboundV6CalloutID;

UINT32 aleInboundV4CalloutID;
UINT32 aleOutboundV4CalloutID;
UINT32 aleInboundV6CalloutID;
UINT32 aleOutboundV6CalloutID;

// Registered?
bool inboundV4CalloutRegistered = false;
bool outboundV4CalloutRegistered = false;
bool inboundV6CalloutRegistered = false;
bool outboundV6CalloutRegistered = false;

bool aleInboundV4CalloutRegistered = false;
bool aleOutboundV4CalloutRegistered = false;
bool aleInboundV6CalloutRegistered = false;
bool aleOutboundV6CalloutRegistered = false;

/** PORTMASTER SUBLAYER **/

NTSTATUS registerSublayer() {

    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.subLayerKey = PORTMASTER_SUBLAYER_GUID;
    sublayer.displayData.name = PORTMASTER_SUBLAYER_NAME;
    sublayer.displayData.description = PORTMASTER_SUBLAYER_DESCRIPTION;
    sublayer.flags = 0;
    sublayer.weight = 0xFFFF;

    NTSTATUS status = FwpmSubLayerAdd(filterEngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        INFO("Could not register Portmaster sublayer: rc=0x%08x", status);
    } else {
        INFO("Portmaster sublayer registered");
    }
    return status;
}

/** PORTMASTER FILTERS **/

NTSTATUS registerFilter(
    FWPM_FILTER* filter,
    UINT64* filterID,
    wchar_t* filterName,
    wchar_t* filterDescription,
    const GUID calloutGUID,
    const GUID layer
) {
    filter->displayData.name = filterName;
    filter->displayData.description = filterDescription;
    filter->action.type = FWP_ACTION_CALLOUT_TERMINATING;   // Says this filter's callout MUST make a block/permit decision. Also see doc excerpts below.
    filter->subLayerKey = PORTMASTER_SUBLAYER_GUID;
    filter->weight.type = FWP_UINT8;
    filter->weight.uint8 = 15;     // The weight of this filter within its sublayer
    filter->flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    filter->numFilterConditions = 0;    // If you specify 0, this filter invokes its callout for all traffic in its layer
    filter->layerKey = layer;   // This layer must match the layer that ExampleCallout is registered to
    filter->action.calloutKey = calloutGUID;
    NTSTATUS status = FwpmFilterAdd(filterEngineHandle, filter, NULL, filterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register Portmaster filter '%ls' functions: rc=0x%08x", filterName, status);
    } else {
        INFO("Portmaster filter registered");
    }

    // From https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
    // A callout and filters that specify the callout for the filter's action can be added to the filter engine before a callout driver registers the callout with the filter engine. In this situation, filters with an action type of FWP_ACTION_CALLOUT_TERMINATING or FWP_ACTION_CALLOUT_UNKNOWN are treated as FWP_ACTION_BLOCK, and filters with an action type of FWP_ACTION_CALLOUT_INSPECTION are ignored until the callout is registered with the filter engine.

    // FWP_ACTION_CALLOUT_TERMINATING directly permits or blocks traffic without asking anyone else.
    // It cannot FWP_ACTION_CONTINUE to the next filter.
    // Source: https://docs.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0

    return status;
}

NTSTATUS registerFilterALE(
    FWPM_FILTER* filter,
    UINT64* filterID,
    wchar_t* filterName,
    wchar_t* filterDescription,
    const GUID calloutGUID,
    const GUID layer
) {
    filter->displayData.name = filterName;
    filter->displayData.description = filterDescription;
    filter->action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter->subLayerKey = PORTMASTER_SUBLAYER_GUID;
    filter->weight.type = FWP_UINT8;
    filter->weight.uint8 = 15;     // The weight of this filter within its sublayer
    filter->flags = FWPM_FILTER_FLAG_NONE;
    filter->numFilterConditions = 0;    // If you specify 0, this filter invokes its callout for all traffic in its layer
    filter->layerKey = layer;   // This layer must match the layer that ExampleCallout is registered to
    filter->action.calloutKey = calloutGUID;
    NTSTATUS status = FwpmFilterAdd(filterEngineHandle, filter, NULL, filterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register Portmaster filter '%ls' functions: rc=0x%08x", filterName, status);
    } else {
        INFO("Portmaster filter registered");
    }

    // From https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
    // A callout and filters that specify the callout for the filter's action can be added to the filter engine before a callout driver registers the callout with the filter engine. In this situation, filters with an action type of FWP_ACTION_CALLOUT_TERMINATING or FWP_ACTION_CALLOUT_UNKNOWN are treated as FWP_ACTION_BLOCK, and filters with an action type of FWP_ACTION_CALLOUT_INSPECTION are ignored until the callout is registered with the filter engine.

    // FWP_ACTION_CALLOUT_TERMINATING directly permits or blocks traffic without asking anyone else.
    // It cannot FWP_ACTION_CONTINUE to the next filter.
    // Source: https://docs.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0

    return status;
}

NTSTATUS registerInboundV4Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilter(&filter, &inboundV4FilterID, INBOUND_V4_FILTER_NAME, INBOUND_V4_FILTER_DESCRIPTION, INBOUND_V4_CALLOUT_GUID, FWPM_LAYER_INBOUND_IPPACKET_V4);
}

NTSTATUS registerOutboundV4Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilter(&filter, &outboundV4FilterID, OUTBOUND_V4_FILTER_NAME, OUTBOUND_V4_FILTER_DESCRIPTION, OUTBOUND_V4_CALLOUT_GUID, FWPM_LAYER_OUTBOUND_IPPACKET_V4);
}

NTSTATUS registerInboundV6Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilter(&filter, &inboundV6FilterID, INBOUND_V6_FILTER_NAME, INBOUND_V6_FILTER_DESCRIPTION, INBOUND_V6_CALLOUT_GUID, FWPM_LAYER_INBOUND_IPPACKET_V6);
}

NTSTATUS registerOutboundV6Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilter(&filter, &outboundV6FilterID, OUTBOUND_V6_FILTER_NAME, OUTBOUND_V6_FILTER_DESCRIPTION, OUTBOUND_V6_CALLOUT_GUID, FWPM_LAYER_OUTBOUND_IPPACKET_V6);
}

// ALE layer
NTSTATUS registerALEInboundV4Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilterALE(&filter, &aleInboundV4FilterID, ALE_INBOUND_V4_FILTER_NAME, ALE_INBOUND_V4_FILTER_DESCRIPTION, ALE_INBOUND_V4_CALLOUT_GUID, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
}

NTSTATUS registerALEOutboundV4Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilterALE(&filter, &aleOutboundV4FilterID, ALE_OUTBOUND_V4_FILTER_NAME, ALE_OUTBOUND_V4_FILTER_DESCRIPTION, ALE_OUTBOUND_V4_CALLOUT_GUID, FWPM_LAYER_ALE_AUTH_CONNECT_V4);
}

NTSTATUS registerALEInboundV6Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilterALE(&filter, &aleInboundV6FilterID, ALE_INBOUND_V6_FILTER_NAME, ALE_INBOUND_V6_FILTER_DESCRIPTION, ALE_INBOUND_V6_CALLOUT_GUID, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
}

NTSTATUS registerALEOutboundV6Filter(DEVICE_OBJECT* wdmDevice) {
    UNREFERENCED_PARAMETER(wdmDevice);
    FWPM_FILTER filter = { 0 };
    return registerFilterALE(&filter, &aleOutboundV6FilterID, ALE_OUTBOUND_V6_FILTER_NAME, ALE_OUTBOUND_V6_FILTER_DESCRIPTION, ALE_OUTBOUND_V6_CALLOUT_GUID, FWPM_LAYER_ALE_AUTH_CONNECT_V6);
}

/** PORTMASTER CALLOUTS **/

NTSTATUS registerCallout(
    DEVICE_OBJECT* wdmDevice,
    FWPS_CALLOUT* sCallout,
    FWPM_CALLOUT* mCallout,
    FWPM_DISPLAY_DATA* displayData,
    UINT32* calloutID,
    BOOL* registered,
    wchar_t* calloutName,
    wchar_t* calloutDescription,
    const GUID calloutGUID,
    void (*callout_fn)(
        const FWPS_INCOMING_VALUES* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const FWPS_FILTER* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT* classifyOut),
    const GUID layer
) {
    if (filterEngineHandle == NULL) {
        return STATUS_INVALID_HANDLE;
    }

    displayData->name = calloutName;
    displayData->description = calloutDescription;

    // Register callout
    sCallout->calloutKey = calloutGUID;
    sCallout->classifyFn = *callout_fn;
    sCallout->notifyFn = genericNotify;
    sCallout->flowDeleteFn = genericFlowDelete;
    NTSTATUS status = FwpsCalloutRegister((void *)wdmDevice, sCallout, calloutID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register %s functions: rc=0x%08x", calloutName, status);
        return status;
    }

    // Register callout manager
    mCallout->calloutKey = calloutGUID;
    mCallout->displayData = *displayData;
    mCallout->applicableLayer = layer;
    mCallout->flags = 0;
    status = FwpmCalloutAdd(filterEngineHandle, mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register Portmaster callout functions: rc=0x%08x", status);
    } else {
        *registered = true;
        // INFO("Portmaster callout registered");
    }
    return status;
}

NTSTATUS registerInboundV4Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &inboundV4CalloutID,
            (BOOL*) &inboundV4CalloutRegistered,
            INBOUND_V4_CALLOUT_NAME,
            INBOUND_V4_CALLOUT_DESCRIPTION,
            INBOUND_V4_CALLOUT_GUID,
            &classifyInboundIPv4,
            FWPM_LAYER_INBOUND_IPPACKET_V4
        );
}

NTSTATUS registerOutboundV4Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &outboundV4CalloutID,
            (BOOL*) &outboundV4CalloutRegistered,
            OUTBOUND_V4_CALLOUT_NAME,
            OUTBOUND_V4_CALLOUT_DESCRIPTION,
            OUTBOUND_V4_CALLOUT_GUID,
            &classifyOutboundIPv4,
            FWPM_LAYER_OUTBOUND_IPPACKET_V4
        );
}

NTSTATUS registerInboundV6Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &inboundV6CalloutID,
            (BOOL*) &inboundV6CalloutRegistered,
            INBOUND_V6_CALLOUT_NAME,
            INBOUND_V6_CALLOUT_DESCRIPTION,
            INBOUND_V6_CALLOUT_GUID,
            &classifyInboundIPv6,
            FWPM_LAYER_INBOUND_IPPACKET_V6
        );
}

NTSTATUS registerOutboundV6Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &outboundV6CalloutID,
            (BOOL*) &outboundV6CalloutRegistered,
            OUTBOUND_V6_CALLOUT_NAME,
            OUTBOUND_V6_CALLOUT_DESCRIPTION,
            OUTBOUND_V6_CALLOUT_GUID,
            &classifyOutboundIPv6,
            FWPM_LAYER_OUTBOUND_IPPACKET_V6
        );
}

// ALE layers
NTSTATUS registerALEInboundV4Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &aleInboundV4CalloutID,
            (BOOL*) &aleInboundV4CalloutRegistered,
            ALE_INBOUND_V4_CALLOUT_NAME,
            ALE_INBOUND_V4_CALLOUT_DESCRIPTION,
            ALE_INBOUND_V4_CALLOUT_GUID,
            &classifyALEInboundIPv4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        );
}

NTSTATUS registerALEOutboundV4Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &aleOutboundV4CalloutID,
            (BOOL*) &aleOutboundV4CalloutRegistered,
            ALE_OUTBOUND_V4_CALLOUT_NAME,
            ALE_OUTBOUND_V4_CALLOUT_DESCRIPTION,
            ALE_OUTBOUND_V4_CALLOUT_GUID,
            &classifyALEOutboundIPv4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4
        );
}

NTSTATUS registerALEInboundV6Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &aleInboundV6CalloutID,
            (BOOL*) &aleInboundV6CalloutRegistered,
            ALE_INBOUND_V6_CALLOUT_NAME,
            ALE_INBOUND_V6_CALLOUT_DESCRIPTION,
            ALE_INBOUND_V6_CALLOUT_GUID,
            &classifyALEInboundIPv6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
        );
}

NTSTATUS registerALEOutboundV6Callout(DEVICE_OBJECT* wdmDevice) {
    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };
    return registerCallout(wdmDevice,
            &sCallout,
            &mCallout,
            &displayData,
            &aleOutboundV6CalloutID,
            (BOOL*) &aleOutboundV6CalloutRegistered,
            ALE_OUTBOUND_V6_CALLOUT_NAME,
            ALE_OUTBOUND_V6_CALLOUT_DESCRIPTION,
            ALE_OUTBOUND_V6_CALLOUT_GUID,
            &classifyALEOutboundIPv6,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6
        );
}

/** EXPORTED **/

NTSTATUS registerWFPStack(DEVICE_OBJECT* wdmDevice) {
    NTSTATUS status = STATUS_SUCCESS;

    // register sublayer

    status = registerSublayer();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // register callouts

    status = registerInboundV4Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerOutboundV4Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerInboundV6Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerOutboundV6Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ALE layer
    status = registerALEInboundV4Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerALEOutboundV4Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerALEInboundV6Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerALEOutboundV6Callout(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // register filters

    status = registerInboundV4Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerOutboundV4Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerInboundV6Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerOutboundV6Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ALE layer
    status = registerALEInboundV4Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerALEOutboundV4Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerALEInboundV6Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = registerALEOutboundV6Filter(wdmDevice);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS unregisterFilters() {
    NTSTATUS status = STATUS_SUCCESS;

    // unregister filters

    status = FwpmFilterDeleteById(filterEngineHandle, inboundV4FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterInboundV4Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, outboundV4FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterOutboundV4Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, inboundV6FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterInboundV6Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, outboundV6FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterOutboundV6Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, aleInboundV4FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterAleInboundV4Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, aleOutboundV4FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterAleOutboundV4Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, aleInboundV6FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterAleInboundV6Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filterEngineHandle, aleOutboundV6FilterID);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterAleOutboundV6Filter: rc=0x%08x", status);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS unregisterCallouts() {
    NTSTATUS status = STATUS_SUCCESS;

    // unregister callouts

    if (inboundV4CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(inboundV4CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterInboundV4Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (outboundV4CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(outboundV4CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterOutboundV4Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (inboundV6CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(inboundV6CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterInboundV6Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (outboundV6CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(outboundV6CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterOutboundV6Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (aleInboundV4CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(aleInboundV4CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterAleInboundV4Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (aleOutboundV4CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(aleOutboundV4CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterAleOutboundV4Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (aleInboundV6CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(aleInboundV6CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterAleInboundV6Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (aleOutboundV6CalloutRegistered == true) {
        status = FwpsCalloutUnregisterById(aleOutboundV6CalloutID);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterAleOutboundV6Callout: rc=0x%08x", status);
            return status;
        }
    }
    return STATUS_SUCCESS;
}
