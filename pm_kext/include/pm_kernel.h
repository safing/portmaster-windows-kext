/*
 *  Name:        pm_kernel.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declarations of Windows Driver entrypoints for Portmaster
 *               Kernel Extension, including DriverEntry, driver_device_control, init_driver_objects
 *
 *  Credits:     Based on the excelent work of
 *                   Jared Wright, https://github.com/JaredWright/WFPStarterKit
 *                   Basil, https://github.com/basil00/Divert
 *
 *  Scope:       Kernelmode
 */

#ifndef PM_KERNEL_H
#define PM_KERNEL_H

#define NDIS61 1                // Need to declare this to compile WFP stuff on Win7, I'm not sure why

#include "Ntifs.h"
#include <ntddk.h>              // Windows Driver Development Kit
#include <wdf.h>                // Windows Driver Foundation

#pragma warning(push)
#pragma warning(disable: 4201)  // Disable "Nameless struct/union" compiler warning for fwpsk.h only!
#include <fwpsk.h>              // Functions and enumerated types used to implement callouts in kernel mode
#pragma warning(pop)            // Re-enable "Nameless struct/union" compiler warning

#include <fwpmk.h>              // Functions used for managing IKE and AuthIP main mode (MM) policy and security associations
#include <fwpvi.h>              // Mappings of OS specific function versions (i.e. fn's that end in 0 or 1)
#include <guiddef.h>            // Used to define GUID's
#include <initguid.h>           // Used to define GUID's
#include "devguid.h"
#include <stdarg.h>
#include <stdbool.h>
#include <ntstrsafe.h>

#include "pm_common.h"

extern PRKQUEUE globalIOQueue;

typedef struct {
    LIST_ENTRY entry;
    PortmasterPacketInfo *packet;
} DataEntry;

extern NTSTATUS IPQueueInitialize(WDFDEVICE Device);
extern void QueueEvtIoRead(IN WDFQUEUE queue, IN WDFREQUEST request, IN size_t length);
extern void QueueEvtIoWrite(IN WDFQUEUE queue, IN WDFREQUEST request, IN size_t length);

#endif // PM_KERNEL_H
