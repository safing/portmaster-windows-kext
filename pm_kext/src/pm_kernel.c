/*
 *  Name:        pm_kernel.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of Windows Driver entrypoints for Portmaster
 *               Kernel Extension, including DriverEntry, driverDeviceControl, InitDriverObject
 *               Uses the Windows Filtering Platform (WFP)
 *               https://docs.microsoft.com/en-us/windows/desktop/FWP/windows-filtering-platform-start-page
 *
 *  Dataflow:
 *  1.) Windows Kernel picks up Packet from TCP/IP Stack (netbuffer).
 *  2.) Windows Kernel presents packet to Portmaster Kernel Extension via callout.
 *  3.) Portmaster Kernel Extension searches verdict for this packet in "verdict_cache",
 *      using IP-Header Data like protocol, source and destination IP and Port
 *  4.) If not found, Portmaster Kernel Extension presents packet to Portmaster Userland
 *      Application via reverse callback "PortmasterRecvVerdictRequest"
 *  5.) Portmaster Userland Application inspects packet_info and sets verdict via
 *      "PortmasterSetVerdict".
 *  6.) If necessary, Portmaster Userland Application may also inspect payload of packet
 *      via "PortmasterGetPayload", using the packet_id previously received by
 *      PortmasterRecvVerdictRequest
 *  7.) Portmaster Kernel Extension holds intercepted packet in packet_cache until the
 *      verdict is set.
 *  8.) If packet_cache is full, first packet will be dropped, so that the lates packet
 *      can be stored.
 *
 *  Credits:     Based on the excellent work of
 *                   Jared Wright, https://github.com/JaredWright/WFPStarterKit
 *                   Basil, https://github.com/basil00/Divert
 *
 *  Scope:       Kernelmode
 */

#include <stdlib.h>

#include "pm_kernel.h"
#include "pm_utils.h"
#define LOGGER_NAME "pm_kernel"
#include "pm_debug.h"

#include "pm_common.h"
#include "pm_callouts.h"
#include "pm_register.h"
#include "pm_netbuffer.h"
#include "packet_cache.h"

//#define __STDC_FORMAT_MACROS
//#include <inttypes.h>


/************************************
    Private Data and Prototypes
************************************/
// Global handle to the WFP Base Filter Engine
HANDLE filterEngineHandle = NULL;

#define PORTMASTER_DEVICE_STRING L"\\Device\\" PORTMASTER_DEVICE_NAME //L"\\Device\\PortmasterKext"
#define PORTMASTER_DOS_DEVICE_STRING L"\\??\\" PORTMASTER_DEVICE_NAME

// Driver entry and exit points
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
EVT_WDF_DRIVER_UNLOAD emptyEventUnload;

//IO CTL
_IRQL_requires_max_(APC_LEVEL)
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH driverDeviceControl;

// Initializes required WDFDriver and WDFDevice objects
NTSTATUS InitDriverObject(DRIVER_OBJECT *driverObject, UNICODE_STRING *registryPath,
    WDFDRIVER *driver, WDFDEVICE *device);

// Global IO Queue for communicating
PRKQUEUE globalIOQueue = NULL;
static LARGE_INTEGER ioQueueTimeout;
#define QUEUE_TIMEOUT_MILI 10000

#define CONNECTIONS_COUNT 1000

/************************************
   Kernel API Functions
************************************/
#pragma warning( push )
// Always disable while making changes to this function!
// FwpmTransactionAbort may fail this will leave filterEngineHandle in locked state. 
// If FwpmTransactionCommit() and FwpmTransactionAbort() fail there is noting else to do to release the lock.
#pragma warning( disable : 26165) // warning C26165: Possibly failing to release lock
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driverObject, IN PUNICODE_STRING registryPath) {
    NTSTATUS status = STATUS_SUCCESS;
    WDFDRIVER driver = { 0 };
    WDFDEVICE device = { 0 };
    DEVICE_OBJECT * wdmDevice = NULL;
    FWPM_SESSION wdfSession = { 0 };
    bool inTransaction = false;
    bool calloutRegistered = false;
    
    initDebugStructure();

    INFO("Trying to load Kernel Object '%ls', Compile date: %s %s", PORTMASTER_DEVICE_NAME, __DATE__, __TIME__);
    INFO("PM_PACKET_CACHE_SIZE = %d, PM_VERDICT_CACHE_SIZE= %d", PM_PACKET_CACHE_SIZE, PM_VERDICT_CACHE_SIZE);
    status = initCalloutStructure();
    if (!NT_SUCCESS(status)) {
        status = STATUS_FAILED_DRIVER_ENTRY;
        goto Exit;
    }

    status = initNetBufferPool();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = InitDriverObject(driverObject, registryPath, &driver, &device);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Begin a transaction to the FilterEngine. You must register objects (filter, callouts, sublayers)
    //to the filter engine in the context of a 'transaction'
    wdfSession.flags = FWPM_SESSION_FLAG_DYNAMIC;  // <-- Automatically destroys all filters and callouts after this wdfSession ends
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdfSession, &filterEngineHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = FwpmTransactionBegin(filterEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    inTransaction = true;

    // Register the all Portmaster Callouts and Filters to the filter engine
    wdmDevice = WdfDeviceWdmGetDeviceObject(device);
    status = registerWFPStack(wdmDevice);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    calloutRegistered = true;

    // Commit transaction to the Filter Engine
    status = FwpmTransactionCommit(filterEngineHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    inTransaction = false;

    // Define this driver's unload function
    driverObject->DriverUnload = DriverUnload;

    // Define IO Control via WDDK's IO Request Packet structure
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driverDeviceControl;


    // Cleanup and handle any errors
Exit:
    if (!NT_SUCCESS(status)) {
        ERR("Portmaster Kernel Extension failed to load, status 0x%08x", status);
        if (inTransaction == true) {
            FwpmTransactionAbort(filterEngineHandle);
            //_Analysis_assume_lock_not_held_(filterEngineHandle); // Potential leak if "FwpmTransactionAbort" fails
        }
        if (calloutRegistered == true) {
            unregisterCallouts();
        }
        status = STATUS_FAILED_DRIVER_ENTRY;
    } else {
        WARN("--- Portmaster Kernel Extension loaded successfully ---");
    }

    return status;
}
#pragma warning( pop ) 

NTSTATUS InitDriverObject(DRIVER_OBJECT * driverObject, UNICODE_STRING * registryPath, WDFDRIVER * driver, WDFDEVICE * device) {
    static const long n100nsTimeCount = 1000 * QUEUE_TIMEOUT_MILI;  //Unit 100ns -> 1s

    UNICODE_STRING deviceName = { 0 };
    RtlInitUnicodeString(&deviceName, PORTMASTER_DEVICE_STRING);

    UNICODE_STRING deviceSymlink = { 0 };
    RtlInitUnicodeString(&deviceSymlink, PORTMASTER_DOS_DEVICE_STRING);

    // Create a WDFDRIVER for this driver
    WDF_DRIVER_CONFIG config = { 0 };
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = emptyEventUnload; // <-- Necessary for this driver to unload correctly
    NTSTATUS status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, driver);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Create a WDFDEVICE for this driver
    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);  // only admins and kernel can access device
    if (!deviceInit) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    // Configure the WDFDEVICE_INIT with a name to allow for access from user mode
    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, false);
    (void) WdfDeviceInitAssignName(deviceInit, &deviceName);
    (void) WdfPdoInitAssignRawDevice(deviceInit, &GUID_DEVCLASS_NET);
    WdfDeviceInitSetDeviceClass(deviceInit, &GUID_DEVCLASS_NET);

    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        goto Exit;
    }
    status = WdfDeviceCreateSymbolicLink(*device, &deviceSymlink);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create device symbolic link: %d", status);
        goto Exit;
    }
    // Initialize a WDF-Queue to transmit questionable packets to userland
    ioQueueTimeout.QuadPart = -1LL * n100nsTimeCount;
    globalIOQueue = portmasterMalloc(sizeof(KQUEUE), false);
    if (globalIOQueue == NULL) {
        ERR("Space for Queue could not be allocated (why?)");
        goto Exit;
    }
    KeInitializeQueue(globalIOQueue, 1);  //Only one (1) thread can be satisfied concurrently while waiting for the queue
    INFO("Queue created");
    /*status= IPQueueInitialize(*device);
    if (!NT_SUCCESS(status))
    {
        ERR("Queue could not be initialized: status= 0x%X", status);
        goto Exit;
    }   */
    WdfControlFinishInitializing(*device);

Exit:
    return status;
}

void DriverUnload(PDRIVER_OBJECT driverObject) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING symlink = { 0 };
    UNREFERENCED_PARAMETER(driverObject);

    INFO("Starting DriverUnload");
    status = unregisterFilters();
    if (!NT_SUCCESS(status)) {
        ERR("Failed to unregister filters, status: 0x%08x", status);
    }
    status = unregisterCallouts();
    if (!NT_SUCCESS(status)) {
        ERR("Failed to unregister callout, status: 0x%08x", status);
    }
    
    destroyCalloutStructure();
    if(globalIOQueue != NULL) {
        portmasterFree(globalIOQueue);
        globalIOQueue = NULL;
    }

    freeNetBufferPool();
    // Close handle to the WFP Filter Engine
    if (filterEngineHandle != NULL) {
        FwpmEngineClose(filterEngineHandle);
        filterEngineHandle = NULL;
    }

    RtlInitUnicodeString(&symlink, PORTMASTER_DOS_DEVICE_STRING);
    IoDeleteSymbolicLink(&symlink);

    INFO("--- Portmaster Kernel Extension unloaded ---");
}

void emptyEventUnload(WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
}

// driverDeviceControl communicates with Userland via
// IO-Request Packets (lrp)
NTSTATUS driverDeviceControl(__in PDEVICE_OBJECT pDeviceObject, __inout PIRP Irp) {
    UNREFERENCED_PARAMETER(pDeviceObject);

    //Set pBuf pointer to Irp->AssociatedIrp.SystemBuffer, which was filled in userland
    //pBuf is also used to return memory from kernel to userland
    void *pBuf = Irp->AssociatedIrp.SystemBuffer;

    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    int IoControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    switch(IoControlCode) {
        case IOCTL_VERSION: {
            char *versionBuffer = (char*)pBuf;
            versionBuffer[0] = PM_VERSION_MAJOR;
            versionBuffer[1] = PM_VERSION_MINOR;
            versionBuffer[2] = PM_VERSION_REVISION;
            versionBuffer[3] = PM_VERSION_BUILD;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 4;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        case IOCTL_SHUTDOWN_REQUEST: {
            INFO("Shutdown request received. Preparing for shutdown ...");
            // Rundown verdict request queue
            PLIST_ENTRY entries = KeRundownQueue(globalIOQueue);
            if(entries != NULL) {
                while(!IsListEmpty(entries)) {
                    DataEntry *dentry = (DataEntry*)RemoveHeadList(entries);
                    portmasterFree(dentry);
                }
            }
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        case IOCTL_RECV_VERDICT_REQ: {
            DEBUG("IOCTL_RECV_VERDICT_REQ");
            PLIST_ENTRY ple = KeRemoveQueue(
                    globalIOQueue,
                    KernelMode, //UserMode, //KernelMode,
                    &ioQueueTimeout
                );
            // Super ugly, but recommended by MS: Callers of KeRemoveQueue should test
            // whether its return value is STATUS_TIMEOUT or STATUS_USER_APC before accessing any entry members.
            NTSTATUS rc = (NTSTATUS) ((UINT64) ple);
            if (rc == STATUS_TIMEOUT) {
                INFO("List was empty -> timeout");
                Irp->IoStatus.Status = STATUS_TIMEOUT;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp,IO_NO_INCREMENT);
                return STATUS_TIMEOUT;
            }
            if (rc == STATUS_USER_APC) {
                INFO("List was empty or not-> STATUS_USER_APC");
                Irp->IoStatus.Status = STATUS_USER_APC;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_USER_APC;
            }
            if (rc == STATUS_ABANDONED) {
                INFO("Queue was rundown-> STATUS_ABANDONED");
                Irp->IoStatus.Status = STATUS_ABANDONED;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_ABANDONED;
            }

            INFO("Sending VERDICT-REQUEST to userland");

            {
                DataEntry *dentry = (DataEntry*)CONTAINING_RECORD(ple, DataEntry, entry);
                int size = sizeof(PortmasterPacketInfo);

                RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
                // Copy message from kernel to pBuf, so that it can be evaluated in userland
                RtlCopyMemory(pBuf, dentry->packet, size);
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = size;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);

                // Now that the contents of the list-entry is copied, free memory
                portmasterFree(dentry);
                return STATUS_SUCCESS;
            }
        }
        case IOCTL_SET_VERDICT: {
            PortmasterVerdictInfo *verdictInfo = (PortmasterVerdictInfo*) pBuf;
            UINT32 id = verdictInfo->id;
            verdict_t verdict = verdictInfo->verdict;

            const char *verdictName = NULL;
            if ((size_t)abs(verdict) < sizeof(VERDICT_NAMES)) {
                verdictName = VERDICT_NAMES[abs(verdict)];
            } else {
                verdictName = "UNDEFINED";
            }
            INFO("Setting verdict %d for packet id %u: %s", verdict, id, verdictName);

            respondWithVerdict(id, verdict);

            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }

        case IOCTL_GET_PAYLOAD: {
            void *packet = NULL;
            size_t packetLength = 0;
            // 0. Make Userland supplied Buffer useable
            PortmasterPayload *payload = (PortmasterPayload*) pBuf;

            INFO("IOCTL_GET_PAYLOAD for id=%u, expect %u Bytes", payload->id, payload->len);
            // 1. Locate packet in packet cache
            NTSTATUS rc = (NTSTATUS)packetCacheGet(getPacketCache(), payload->id, &packet, &packetLength);

            // 2. Sanity Checks
            if (rc != 0) {
                // packet id was not in packet cache
                WARN("packet_id unknown: %u -> STATUS_OBJECT_NAME_NOT_FOUND", payload->id);
                rc = STATUS_OBJECT_NAME_NOT_FOUND; //->Maps to Userland via GetLastError "ERROR_FILE_NOT_FOUND";
                Irp->IoStatus.Information = 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }
            if ((packetLength == 0) || (!packet)) {
                WARN("packet_id=%d, but packetLength= %u, packet=null", payload->id, packetLength);
                rc = STATUS_INVALID_PARAMETER; //->Maps to Userland via GetLastError "??";
                Irp->IoStatus.Information = 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }

            if (packetLength != payload->len && packetLength != pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength) {
                WARN("Caller supplied buffer(%u Bytes) for id=%u too small for packet(%u Bytes) -> STATUS_INSUFFICIENT_RESOURCES", payload->len, payload->id, packetLength);
                rc = STATUS_INSUFFICIENT_RESOURCES; //->Maps to Userland via GetLastError "ERROR_NO_SYSTEM_RESOURCES"
                Irp->IoStatus.Information = 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }
            if (packetLength > MAX_PAYLOAD_SIZE) {
                WARN("Oh no");
                rc = STATUS_INSUFFICIENT_RESOURCES; //->Maps to Userland via GetLastError "ERROR_NO_SYSTEM_RESOURCES"
                Irp->IoStatus.Information = 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }

            // 3. Copy Packet to user supplied buffer
            rc = STATUS_SUCCESS;
            INFO("Retrieved packet for id=%u, len=%u, rc=%d", payload->id, packetLength, rc);
            //RtlZeroMemory(pBuf, packetLength);
            RtlCopyMemory(pBuf, packet, packetLength);

            //Finish the I/O operation by simply completing the packet and returning
            //the same status as in the packet itself.
            Irp->IoStatus.Information = packetLength;

IOCTL_GET_PAYLOAD_EXIT:
            //Irp->IoStatus.Information is the ONLY way to transfer status information to userland
            //We need to share it with "Bytes Transferred".  That is why we ignore the (unsigned) type
            //of Irp->IoStatus.Information and use the first (sign) Bit to distinguish between
            // (0) Bytes Transferred and
            // (1) Status
            //Irp->IoStatus.Status is only used internally and cannot be accessed by userland
            //Latest Enlightenments proof this hypothesis wrong: There seems to be some mapping
            //between NT-Status Codes and Userland Status Codes!
            Irp->IoStatus.Status = rc;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return rc;
        }
        case IOCTL_CLEAR_CACHE: {
            clearCache();
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        case IOCTL_UPDATE_VERDICT: {
            VerdictUpdateInfo *verdictUpdateInfo = (VerdictUpdateInfo*)pBuf;
            updateVerdict(verdictUpdateInfo);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        case IOCTL_GET_CONNECTIONS_STATS: {
            UINT32 *arraySize = (UINT32*) pBuf;
            PortmasterConnection *connections = (PortmasterConnection *) pBuf;
            int writeCount = getConnectionsStats(connections, *arraySize);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = writeCount * sizeof(PortmasterConnection);
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        default: {
            ERR("Don't know how to deal with IoControlCode 0x%x", IoControlCode);
            Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_NOT_IMPLEMENTED;
        }
    }
}
