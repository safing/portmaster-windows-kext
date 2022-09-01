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

#ifndef PM_REGISTER_H
#define PM_REGISTER_H

#include "pm_kernel.h"
#include "pm_callouts.h"

NTSTATUS registerWFPStack(DEVICE_OBJECT* wdmDevice);
NTSTATUS unregisterFilters();
NTSTATUS unregisterCallouts();

#endif // PM_REGISTER_H
