/*
 *  Name:        pm_register.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declarations for rgistering filters and
 *               callouts for the kernel using the mechanisms supplied by
 *               Windows Filtering Platform
 *
 *  Scope:       Kernelmode
 */

#ifndef WFPDriver_H
#define WFPDriver_H

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

#endif // include guard


#ifndef SYS_REGISTER_H
#define SYS_REGISTER_H

#include "pm_kernel.h"
#include "pm_callouts.h"

NTSTATUS registerWFPStack(DEVICE_OBJECT* wdmDevice);
NTSTATUS unregisterFilters();
NTSTATUS unregisterCallouts();

#endif // include guard
