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

extern HANDLE filter_engine_handle;

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

// Assigned filter IDs by engine
UINT64 inbound_v4_filter_id;
UINT64 outbound_v4_filter_id;
UINT64 inbound_v6_filter_id;
UINT64 outbound_v6_filter_id;

// Callout Names
#define INBOUND_V4_CALLOUT_NAME         L"PortmasterInboundV4Callout"
#define INBOUND_V4_CALLOUT_DESCRIPTION  L"This callout is used by the Portmaster to intercept inbound IPv4 traffic."
#define OUTBOUND_V4_CALLOUT_NAME        L"PortmasterOutboundV4Callout"
#define OUTBOUND_V4_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to intercept outbound IPv4 traffic."
#define INBOUND_V6_CALLOUT_NAME         L"PortmasterInboundV6Callout"
#define INBOUND_V6_CALLOUT_DESCRIPTION  L"This callout is used by the Portmaster to intercept inbound IPv6 traffic."
#define OUTBOUND_V6_CALLOUT_NAME        L"PortmasterOutboundV6Callout"
#define OUTBOUND_V6_CALLOUT_DESCRIPTION L"This callout is used by the Portmaster to intercept outbound IPv6 traffic."

// GUIDs
DEFINE_GUID(INBOUND_V4_CALLOUT_GUID,  0x05c55149, 0x4732, 0x4857, 0x8d, 0x10, 0xf1, 0x78, 0xf3, 0xa0, 0x6f, 0x8c); // 05c55149-4732-4857-8d10-f178f3a06f8c
DEFINE_GUID(OUTBOUND_V4_CALLOUT_GUID, 0x41162b9e, 0x8473, 0x4b88, 0xa5, 0xeb, 0x04, 0xcf, 0x1d, 0x27, 0x6b, 0x06); // 41162b9e-8473-4b88-a5eb-04cf1d276b06
DEFINE_GUID(INBOUND_V6_CALLOUT_GUID,  0xceff1df7, 0x2baa, 0x44c5, 0xa6, 0xe5, 0x73, 0xa9, 0x58, 0x49, 0xbc, 0xff); // ceff1df7-2baa-44c5-a6e5-73a95849bcff
DEFINE_GUID(OUTBOUND_V6_CALLOUT_GUID, 0x32bad112, 0x6af4, 0x4109, 0x80, 0x9b, 0xc0, 0x75, 0x70, 0xba, 0x01, 0xb4); // 32bad112-6af4-4109-809b-c07570ba01b4

// Assigned callout IDs by engine
UINT32 inbound_v4_callout_id;
UINT32 outbound_v4_callout_id;
UINT32 inbound_v6_callout_id;
UINT32 outbound_v6_callout_id;

// Registered?
BOOLEAN inbound_v4_callout_registered = FALSE;
BOOLEAN outbound_v4_callout_registered = FALSE;
BOOLEAN inbound_v6_callout_registered = FALSE;
BOOLEAN outbound_v6_callout_registered = FALSE;

/** PORTMASTER SUBLAYER **/

NTSTATUS register_sublayer() {
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SUBLAYER sublayer = { 0 };

    sublayer.subLayerKey = PORTMASTER_SUBLAYER_GUID;
    sublayer.displayData.name = PORTMASTER_SUBLAYER_NAME;
    sublayer.displayData.description = PORTMASTER_SUBLAYER_DESCRIPTION;
    sublayer.flags = 0;
    sublayer.weight = 0x0f;
    status = FwpmSubLayerAdd(filter_engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        // INFO("Could not register Portmaster sublayer: rc=0x%08x", status);
    } else {
        // INFO("Portmaster sublayer registered");
    }
    return status;
}

/** PORTMASTER FILTERS **/

NTSTATUS register_filter(
    FWPM_FILTER* filter,
    UINT64* filter_id,
    wchar_t* filter_name,
    wchar_t* filter_description,
    const GUID callout_guid,
    const GUID layer
) {
    NTSTATUS status = STATUS_SUCCESS;

    filter->displayData.name = filter_name;
    filter->displayData.description = filter_description;
    filter->action.type = FWP_ACTION_CALLOUT_TERMINATING;   // Says this filter's callout MUST make a block/permit decision
    filter->subLayerKey = PORTMASTER_SUBLAYER_GUID;
    filter->weight.type = FWP_UINT8;
    filter->weight.uint8 = 0xf;     // The weight of this filter within its sublayer
    filter->numFilterConditions = 0;    // If you specify 0, this filter invokes its callout for all traffic in its layer
    filter->layerKey = layer;   // This layer must match the layer that ExampleCallout is registered to
    filter->action.calloutKey = callout_guid;
    status = FwpmFilterAdd(filter_engine_handle, filter, NULL, filter_id);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register Portmaster filter '%ls' functions: rc=0x%08x", filter_name, status);
    } else {
        // INFO("Portmaster filter registered");
    }

    return status;
}

NTSTATUS register_inbound_v4_filter(DEVICE_OBJECT* wdm_device) {
    FWPM_FILTER filter = { 0 };
    return register_filter(&filter, &inbound_v4_filter_id, INBOUND_V4_FILTER_NAME, INBOUND_V4_FILTER_DESCRIPTION, INBOUND_V4_CALLOUT_GUID, FWPM_LAYER_INBOUND_IPPACKET_V4);
}

NTSTATUS register_outbound_v4_filter(DEVICE_OBJECT* wdm_device) {
    FWPM_FILTER filter = { 0 };
    return register_filter(&filter, &outbound_v4_filter_id, OUTBOUND_V4_FILTER_NAME, OUTBOUND_V4_FILTER_DESCRIPTION, OUTBOUND_V4_CALLOUT_GUID, FWPM_LAYER_OUTBOUND_IPPACKET_V4);
}

NTSTATUS register_inbound_v6_filter(DEVICE_OBJECT* wdm_device) {
    FWPM_FILTER filter = { 0 };
    return register_filter(&filter, &inbound_v6_filter_id, INBOUND_V6_FILTER_NAME, INBOUND_V6_FILTER_DESCRIPTION, INBOUND_V6_CALLOUT_GUID, FWPM_LAYER_INBOUND_IPPACKET_V6);
}

NTSTATUS register_outbound_v6_filter(DEVICE_OBJECT* wdm_device) {
    FWPM_FILTER filter = { 0 };
    return register_filter(&filter, &outbound_v6_filter_id, OUTBOUND_V6_FILTER_NAME, OUTBOUND_V6_FILTER_DESCRIPTION, OUTBOUND_V6_CALLOUT_GUID, FWPM_LAYER_OUTBOUND_IPPACKET_V6);
}

/** PORTMASTER CALLOUTS **/

NTSTATUS register_callout(
    DEVICE_OBJECT* wdm_device,
    FWPS_CALLOUT* s_callout,
    FWPM_CALLOUT* m_callout,
    FWPM_DISPLAY_DATA* display_data,
    UINT32* callout_id,
    BOOLEAN* registered,
    wchar_t* callout_name,
    wchar_t* callout_description,
    const GUID callout_guid,
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
    NTSTATUS status = STATUS_SUCCESS;

    if (filter_engine_handle == NULL) {
        return STATUS_INVALID_HANDLE;
    }

    display_data->name = callout_name;
    display_data->description = callout_description;

    // Register callout
    s_callout->calloutKey = callout_guid;
    s_callout->classifyFn = *callout_fn;
    s_callout->notifyFn = genericNotify;
    s_callout->flowDeleteFn = genericFlowDelete;
    status = FwpsCalloutRegister((void *)wdm_device, s_callout, callout_id);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register PortmasterInboundV4Callout functions: rc=0x%08x", status);
        return status;
    }

    // Register callout manager
    m_callout->calloutKey = callout_guid;
    m_callout->displayData = *display_data;
    m_callout->applicableLayer = layer;
    m_callout->flags = 0;
    status = FwpmCalloutAdd(filter_engine_handle, m_callout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        ERR("Could not register Portmaster callout functions: rc=0x%08x", status);
    } else {
        *registered = TRUE;
        // INFO("Portmaster callout registered");
    }
    return status;
}

NTSTATUS register_inbound_v4_callout(DEVICE_OBJECT* wdm_device) {
    FWPS_CALLOUT s_callout = { 0 };
    FWPM_CALLOUT m_callout = { 0 };
    FWPM_DISPLAY_DATA display_data = { 0 };
    return register_callout(wdm_device,
            &s_callout,
            &m_callout,
            &display_data,
            &inbound_v4_callout_id,
            &inbound_v4_callout_registered,
            INBOUND_V4_CALLOUT_NAME,
            INBOUND_V4_CALLOUT_DESCRIPTION,
            INBOUND_V4_CALLOUT_GUID,
            &classifyInboundIPv4,
            FWPM_LAYER_INBOUND_IPPACKET_V4
        );
}

NTSTATUS register_outbound_v4_callout(DEVICE_OBJECT* wdm_device) {
    FWPS_CALLOUT s_callout = { 0 };
    FWPM_CALLOUT m_callout = { 0 };
    FWPM_DISPLAY_DATA display_data = { 0 };
    return register_callout(wdm_device,
            &s_callout,
            &m_callout,
            &display_data,
            &outbound_v4_callout_id,
            &outbound_v4_callout_registered,
            OUTBOUND_V4_CALLOUT_NAME,
            OUTBOUND_V4_CALLOUT_DESCRIPTION,
            OUTBOUND_V4_CALLOUT_GUID,
            &classifyOutboundIPv4,
            FWPM_LAYER_OUTBOUND_IPPACKET_V4
        );
}

NTSTATUS register_inbound_v6_callout(DEVICE_OBJECT* wdm_device) {
    FWPS_CALLOUT s_callout = { 0 };
    FWPM_CALLOUT m_callout = { 0 };
    FWPM_DISPLAY_DATA display_data = { 0 };
    return register_callout(wdm_device,
            &s_callout,
            &m_callout,
            &display_data,
            &inbound_v6_callout_id,
            &inbound_v6_callout_registered,
            INBOUND_V6_CALLOUT_NAME,
            INBOUND_V6_CALLOUT_DESCRIPTION,
            INBOUND_V6_CALLOUT_GUID,
            &classifyInboundIPv6,
            FWPM_LAYER_INBOUND_IPPACKET_V6
        );
}

NTSTATUS register_outbound_v6_callout(DEVICE_OBJECT* wdm_device) {
    FWPS_CALLOUT s_callout = { 0 };
    FWPM_CALLOUT m_callout = { 0 };
    FWPM_DISPLAY_DATA display_data = { 0 };
    return register_callout(wdm_device,
            &s_callout,
            &m_callout,
            &display_data,
            &outbound_v6_callout_id,
            &outbound_v6_callout_registered,
            OUTBOUND_V6_CALLOUT_NAME,
            OUTBOUND_V6_CALLOUT_DESCRIPTION,
            OUTBOUND_V6_CALLOUT_GUID,
            &classifyOutboundIPv6,
            FWPM_LAYER_OUTBOUND_IPPACKET_V6
        );
}

/** EXPORTED **/

NTSTATUS register_wfp_stack(DEVICE_OBJECT* wdm_device) {
    NTSTATUS status = STATUS_SUCCESS;

    // register sublayer

    status = register_sublayer();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // register callouts

    status = register_inbound_v4_callout(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_outbound_v4_callout(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_inbound_v6_callout(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_outbound_v6_callout(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // register filters

    status = register_inbound_v4_filter(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_outbound_v4_filter(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_inbound_v6_filter(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_outbound_v6_filter(wdm_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return status;
}

NTSTATUS unregister_filters() {
    NTSTATUS status = STATUS_SUCCESS;

    // unregister filters

    status = FwpmFilterDeleteById(filter_engine_handle, inbound_v4_filter_id);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterInboundV4Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filter_engine_handle, outbound_v4_filter_id);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterOutboundV4Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filter_engine_handle, inbound_v6_filter_id);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterInboundV6Filter: rc=0x%08x", status);
        return status;
    }

    status = FwpmFilterDeleteById(filter_engine_handle, outbound_v6_filter_id);
    if (!NT_SUCCESS(status)) {
        ERR("Could not unregister PortmasterOutboundV6Filter: rc=0x%08x", status);
        return status;
    }

    return status;
}

NTSTATUS unregister_callouts() {
    NTSTATUS status = STATUS_SUCCESS;

    // unregister callouts

    if (inbound_v4_callout_registered == TRUE) {
        status = FwpsCalloutUnregisterById(inbound_v4_callout_id);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterInboundV4Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (outbound_v4_callout_registered == TRUE) {
        status = FwpsCalloutUnregisterById(outbound_v4_callout_id);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterOutboundV4Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (inbound_v6_callout_registered == TRUE) {
        status = FwpsCalloutUnregisterById(inbound_v6_callout_id);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterInboundV6Callout: rc=0x%08x", status);
            return status;
        }
    }

    if (outbound_v6_callout_registered == TRUE) {
        status = FwpsCalloutUnregisterById(outbound_v6_callout_id);
        if (!NT_SUCCESS(status)) {
            ERR("Could not unregister PortmasterOutboundV6Callout: rc=0x%08x", status);
            return status;
        }
    }

    return status;
}
