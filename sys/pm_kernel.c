/*
 *  Name:        pm_kernel.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of Windows Driver entrypoints for Portmaster
 *               Kernel Extension, including DriverEntry, driver_device_control, init_driver_objects
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
 *  Credits:     Based on the excelent work of
 *                   Jared Wright, https://github.com/JaredWright/WFPStarterKit
 *                   Basil, https://github.com/basil00/Divert
 *
 *  Scope:       Kernelmode
 */

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
HANDLE filter_engine_handle = NULL;

#define PORTMASTER_DEVICE_STRING L"\\Device\\" PORTMASTER_DEVICE_NAME //L"\\Device\\PortmasterKext"
#define PORTMASTER_DOS_DEVICE_STRING L"\\??\\" PORTMASTER_DEVICE_NAME

// Driver entry and exit points
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
EVT_WDF_DRIVER_UNLOAD empty_evt_unload;

//IO CTL
NTSTATUS driver_device_control(__in PDEVICE_OBJECT  pDeviceObject, __inout PIRP Irp);

// Initializes required WDFDriver and WDFDevice objects
NTSTATUS init_driver_objects(DRIVER_OBJECT * driver_obj, UNICODE_STRING * registry_path,
    WDFDRIVER * driver, WDFDEVICE * device);

// shared mem to communicate between callout -> device_control -> userland
char global_buf[256];

// Global IO Queue for communi
PRKQUEUE global_io_queue;
static LARGE_INTEGER io_queue_timeout;
#define QUEUE_TIMEOUT_MILI 10000


/************************************
   Kernel API Functions
************************************/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver_obj, IN PUNICODE_STRING registry_path) {
    NTSTATUS status = STATUS_SUCCESS;
    WDFDRIVER driver = { 0 };
    WDFDEVICE device = { 0 };
    DEVICE_OBJECT * wdm_device = NULL;
    FWPM_SESSION wdf_session = { 0 };
    BOOLEAN in_transaction = FALSE;
    BOOLEAN callout_registered = FALSE;

    INFO("Trying to load Kernel Object '%ls', Compiledate: %s %s", PORTMASTER_DEVICE_NAME, __DATE__, __TIME__);
    status= initCalloutStructure();
    if (!NT_SUCCESS(status)) {
        status = STATUS_FAILED_DRIVER_ENTRY;
        goto Exit;
    }

    status= init_netbufferpool();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = init_driver_objects(driver_obj, registry_path, &driver, &device);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Begin a transaction to the FilterEngine. You must register objects (filter, callouts, sublayers)
    //to the filter engine in the context of a 'transaction'
    wdf_session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // <-- Automatically destroys all filters and callouts after this wdf_session ends
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdf_session, &filter_engine_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = FwpmTransactionBegin(filter_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    in_transaction = TRUE;

    // Register the all Portmaster Callouts and Filters to the filter engine
    wdm_device = WdfDeviceWdmGetDeviceObject(device);
    status = register_wfp_stack(wdm_device);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    callout_registered = TRUE;

    // Commit transaction to the Filter Engine
    status = FwpmTransactionCommit(filter_engine_handle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    in_transaction = FALSE;

    // Define this driver's unload function
    driver_obj->DriverUnload = DriverUnload;

    // Define IO Control via WDDK's IO Request Packet structure
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_device_control;



    // Cleanup and handle any errors
Exit:
    if (!NT_SUCCESS(status)) {
        ERR("Portmaster Kernel Extenstion failed to load, status 0x%08x", status);
        if (in_transaction == TRUE) {
            FwpmTransactionAbort(filter_engine_handle);
            //_Analysis_assume_lock_not_held_(filter_engine_handle); // Potential leak if "FwpmTransactionAbort" fails
        }
        if (callout_registered == TRUE) {
            unregister_callouts();
        }
        status = STATUS_FAILED_DRIVER_ENTRY;
    } else {
        WARN("--- Portmaster Kernel Extenstion loaded successfully ---");
    }

    return status;
}

NTSTATUS init_driver_objects(DRIVER_OBJECT * driver_obj, UNICODE_STRING * registry_path,
    WDFDRIVER * driver, WDFDEVICE * device) {
    NTSTATUS status = STATUS_SUCCESS;
    WDF_DRIVER_CONFIG config = { 0 };
    UNICODE_STRING device_name = { 0 };
    UNICODE_STRING device_symlink = { 0 };
    PWDFDEVICE_INIT device_init = NULL;
    static const long n100nsTimeCount= 1000 * QUEUE_TIMEOUT_MILI;  //Unit 100ns -> 1s

    RtlInitUnicodeString(&device_name, PORTMASTER_DEVICE_STRING);
    RtlInitUnicodeString(&device_symlink, PORTMASTER_DOS_DEVICE_STRING);

    // Create a WDFDRIVER for this driver
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = empty_evt_unload; // <-- Necessary for this driver to unload correctly
    status = WdfDriverCreate(driver_obj, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &config, driver);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Create a WDFDEVICE for this driver
    device_init = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);  // only admins and kernel can access device
    if (!device_init) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    // Configure the WDFDEVICE_INIT with a name to allow for access from user mode
    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(device_init, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitAssignName(device_init, &device_name);
    WdfPdoInitAssignRawDevice(device_init, &GUID_DEVCLASS_NET);
    WdfDeviceInitSetDeviceClass(device_init, &GUID_DEVCLASS_NET);

    status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(device_init);
        goto Exit;
    }
    status = WdfDeviceCreateSymbolicLink(*device, &device_symlink);
    if (!NT_SUCCESS(status)) {
        ERR("failed to create device symbolic link: %d", status);
        goto Exit;
    }
    // Initialize a WDF-Queue to transmit questionable packets to userland
    io_queue_timeout= RtlConvertLongToLargeInteger(-1 * n100nsTimeCount);
    global_io_queue= portmaster_malloc(sizeof(KQUEUE), FALSE);
    if (global_io_queue == NULL) {
        ERR("Space for Queue could not be allocated (why?)");
        goto Exit;
    }
    KeInitializeQueue(global_io_queue, 1);  //Only one (1) thread can be satisfied concurrently while waiting for the queue
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

VOID DriverUnload(PDRIVER_OBJECT driver_obj) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING symlink = { 0 };
    UNREFERENCED_PARAMETER(driver_obj);

    INFO("Starting DriverUnload");
    status = unregister_filters();
    if (!NT_SUCCESS(status)) {
        ERR("Failed to unregister filters, status: 0x%08x", status);
    }
    status = unregister_callouts();
    if (!NT_SUCCESS(status)) {
        ERR("Failed to unregister callout, status: 0x%08x", status);
    }
    destroyCalloutStructure();

    free_netbufferpool();
    // Close handle to the WFP Filter Engine
    if (filter_engine_handle) {
        FwpmEngineClose(filter_engine_handle);
        filter_engine_handle = NULL;
    }

    RtlInitUnicodeString(&symlink, PORTMASTER_DOS_DEVICE_STRING);
    IoDeleteSymbolicLink(&symlink);

    INFO("--- Portmaster Kernel Extension unloaded ---");
    return;
}

VOID empty_evt_unload(WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    return;
}

// driver_device_control communicates with Userland via
// IO-Request Packets (lrp)
NTSTATUS driver_device_control(__in PDEVICE_OBJECT  pDeviceObject, __inout PIRP Irp) {
    NTSTATUS rc;
    PIO_STACK_LOCATION pIoStackLocation;
    //Set pBuf pointer to Irp->AssociatedIrp.SystemBuffer, which was filled in userland
    //pBuf is also used to return memory from kernel to userland
    PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
    int IoControlCode;

    pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    IoControlCode= pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    switch(IoControlCode) {
#ifdef DEBUG_ON
        //Hello World with ke-us shared memory "Irp->AssociatedIrp.SystemBuffer"
        case IOCTL_HELLO: {
            const PCHAR welcome = "Hello from kerneland.";
            LARGE_INTEGER li;
            long n100nsTimeCount= 70000000;
            li= RtlConvertLongToLargeInteger(-1 * n100nsTimeCount);  //WTF?
            INFO("IOCTL HELLO");
            rc= KeDelayExecutionThread(
                    UserMode, //KPROCESSOR_MODE WaitMode, KernelMode
                    TRUE,   //Alterable
                    &li //Unit: 100ns
                );
            INFO("Message received : %s", pBuf);
            rc= KeDelayExecutionThread(
                    KernelMode, //KPROCESSOR_MODE WaitMode,
                    FALSE,  //Alterable
                    &li //Unit: 100ns
                );
            RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
            //Copy message from kernel to pBuf, so that it can be evaluated in userland
            RtlCopyMemory(pBuf, welcome, strlen(welcome) );
            //Finish the I/O operation by simply completing the packet and returning
            //the same status as in the packet itself.
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = strlen(welcome);
            IoCompleteRequest(Irp,IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }

        case IOCTL_RECV_VERDICT_REQ_POLL: {
            int len;
            DEBUG("IOCTL_RECV_VERDICT_REQ_POLL");
            len= strlen(global_buf);
            if (len > 0) {
                RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
                //Copy message from kernel to pBuf, so that it can be evaluated in userland
                RtlCopyMemory(pBuf, global_buf, strlen(global_buf) );
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = strlen(global_buf);
                IoCompleteRequest(Irp,IO_NO_INCREMENT);
                RtlZeroMemory(global_buf, sizeof(global_buf));
                return STATUS_SUCCESS;
            }
            Irp->IoStatus.Status = STATUS_TIMEOUT;
            IoCompleteRequest(Irp,IO_NO_INCREMENT);
            return STATUS_TIMEOUT;
        }
#endif
        case IOCTL_RECV_VERDICT_REQ: {
            int len;
            NTSTATUS rc;
            //WDFREQUEST request;
            PLIST_ENTRY ple;

            DEBUG("IOCTL_RECV_VERDICT_REQ");
            ple= KeRemoveQueue(
                    global_io_queue,
                    KernelMode, //UserMode, //KernelMode,
                    &io_queue_timeout
                );
            //Super ugly, but recommended by MS: Callers of KeRemoveQueue should test
            //whether its return value is STATUS_TIMEOUT or STATUS_USER_APC before accessing any entry members.
            rc= (NTSTATUS) ple;
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
                IoCompleteRequest(Irp,IO_NO_INCREMENT);
                return STATUS_USER_APC;
            }
            INFO("Sending VERDICT-REQUEST to userland");
            {
                PDATA_ENTRY dentry = (PDATA_ENTRY)CONTAINING_RECORD(ple, DATA_ENTRY, entry);
                int size= sizeof(portmaster_packet_info);

                RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
                //Copy message from kernel to pBuf, so that it can be evaluated in userland
                RtlCopyMemory(pBuf, dentry->ppacket, size);
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = size;
                IoCompleteRequest(Irp,IO_NO_INCREMENT);

                //Now that the contents of the list-entry is copied, free memory
                portmaster_free(dentry);
                return STATUS_SUCCESS;
            }
        }
        case IOCTL_SET_VERDICT: {
            UINT32 id;
            verdict_t verdict;
            const char* verdict_name;
            const char* verdict_names[]= VERDICT_NAMES;

            pportmaster_verdict_info verdict_info= (pportmaster_verdict_info) pBuf;
            id= verdict_info->id;
            verdict= verdict_info->verdict;
            if (abs(verdict) < sizeof(verdict_names)) {
                verdict_name= verdict_names[abs(verdict)];
            } else {
                verdict_name= "UNDEFINED";
            }
            INFO("Setting verdict %d for packet id %u: %s", verdict, id, verdict_name);

            respondWithVerdict(id, verdict);

            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp,IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }

        case IOCTL_GET_PAYLOAD: {
            UINT32 rc;
            void* packet;
            size_t packet_len;
            KLOCK_QUEUE_HANDLE lock_handle;
            // 0. Make Userland supplied Buffer useable
            pportmaster_payload pp= (pportmaster_payload) pBuf;

            INFO("IOCTL_GET_PAYLOAD for id=%u, expect %u Bytes", pp->id, pp->len);
            // 1. Locate packet in packet_cache
            KeAcquireInStackQueuedSpinLock(&packetCacheLock, &lock_handle);
            rc = get_packet(packetCache, pp->id, &packet, &packet_len);

            // 2. Sanity Checks
            if (rc != 0) {
                // packet id was not in packet cache
                WARN("packet_id unknown: %u -> STATUS_OBJECT_NAME_NOT_FOUND", pp->id);
                rc= STATUS_OBJECT_NAME_NOT_FOUND; //->Maps to Userland via GetLastError "ERROR_FILE_NOT_FOUND";
                Irp->IoStatus.Information= 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }
            if ((packet_len == 0) || (!packet)) {
                WARN("packet_id=%d, but packet_len= %u, packet=null", pp->id, packet_len);
                rc= STATUS_INVALID_PARAMETER; //->Maps to Userland via GetLastError "??";
                Irp->IoStatus.Information= 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }

            if (packet_len != pp->len && packet_len != pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength) {
                WARN("Caller supplied buffer(%u Bytes) for id=%u too small for packet(%u Bytes) -> STATUS_INSUFFICIENT_RESOURCES", pp->len, pp->id, packet_len);
                rc= STATUS_INSUFFICIENT_RESOURCES; //->Maps to Userland via GetLastError "ERROR_NO_SYSTEM_RESOURCES"
                Irp->IoStatus.Information= 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }
            if (packet_len > MAX_PAYLOAD_SIZE) {
                WARN("Oh no");
                rc= STATUS_INSUFFICIENT_RESOURCES; //->Maps to Userland via GetLastError "ERROR_NO_SYSTEM_RESOURCES"
                Irp->IoStatus.Information= 0;
                goto IOCTL_GET_PAYLOAD_EXIT;
            }

            // 3. Copy Packet to user supplied buffer
            rc= STATUS_SUCCESS;
            INFO("Retrieved packet for id=%u, len=%u, rc=%d", pp->id, packet_len, rc);
            //RtlZeroMemory(pBuf, packet_len);
            RtlCopyMemory(pBuf, packet, packet_len);

            //Finish the I/O operation by simply completing the packet and returning
            //the same status as in the packet itself.
            Irp->IoStatus.Information = packet_len;

IOCTL_GET_PAYLOAD_EXIT:
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            //Irp->IoStatus.Information is the ONLY way to transfer status information to userland
            //We need to share it with "Bytes Transfered".  That is why we ignore the (unsigned) type
            //of Irp->IoStatus.Information and use the first (sign) Bit to distinguish between
            // (0) Bytes Transfered and
            // (1) Status
            //Irp->IoStatus.Status is only used internally and cannot be accessed by userland
            //Latest Enlightenments proof this hypothesis wrong: There seems to be some mapping
            //between NT-Status Codes and Userland Status Codes!
            Irp->IoStatus.Status = rc;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return rc;
        }

        default: {
            ERR("Don't know how to deal with IoControlCode 0x%x", IoControlCode);
            Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
            IoCompleteRequest(Irp,IO_NO_INCREMENT);
            return STATUS_NOT_IMPLEMENTED;
        }
    }
}
