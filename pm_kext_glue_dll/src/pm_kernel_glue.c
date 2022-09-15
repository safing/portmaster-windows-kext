/*
 *  Name:        pm_kernel_glue.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation for communication with kernel module
 *               via IRP (https://msdn.microsoft.com/en-us/library/windows/hardware/ff550694(v=vs.85).aspx)
 *
 *  Scope:       Userland
 */

#ifndef UNICODE
#define UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "pm_kernel_glue.h"

#include "pm_common.h"
#include "pm_api.h"
#define LOGGER_NAME "PM_KE_GLUE"
#include "pm_debug.h"
#include "pm_debug_dll.h"

#define PORTMASTER_DRIVER_NAME           L"pm_kernel64.sys"


#ifndef UINT8_MAX
#define UINT8_MAX       0xFF
#endif
#ifndef UINT32_MAX
#define UINT32_MAX      0xFFFFFFFF
#endif

/*
 * Prototypes.
 */
static SC_HANDLE portmasterDriverInstall(const char* portmasterKextPath);

/*
 * Thread local.
 */
static DWORD portmasterTLSIndex;

/*
 * Current DLL hmodule.
 */
static HMODULE module = NULL;

/*
 * Dll Entry
 */
extern _EXPORT bool APIENTRY portmasterDllEntry(HANDLE module0, DWORD reason, LPVOID reserved) {
    HANDLE event = INVALID_HANDLE_VALUE;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            module = module0;
            if ((portmasterTLSIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
                return false;
            }
        // Fallthrough
        case DLL_THREAD_ATTACH:
            event = CreateEvent(NULL, false, false, NULL);
            if (event == NULL) {
                return false;
            }
            TlsSetValue(portmasterTLSIndex, (LPVOID)event);
            break;

        case DLL_PROCESS_DETACH:
            event = (HANDLE)TlsGetValue(portmasterTLSIndex);
            if (event != (HANDLE)NULL) {
                CloseHandle(event);
            }
            TlsFree(portmasterTLSIndex);
            break;

        case DLL_THREAD_DETACH:
            event = (HANDLE)TlsGetValue(portmasterTLSIndex);
            if (event != (HANDLE)NULL) {
                CloseHandle(event);
            }
            break;
    }
    return true;
}


/*
 * Locate the portmaster driver files and copy filename with path to sysFilePath
 */
static bool getDriverFileName(LPWSTR sysFilePath) {
    size_t dirPathLength = 0;
    size_t sysFilenameLength = 0;

    if (!pmStrLen(PORTMASTER_DRIVER_NAME, MAX_PATH, &sysFilenameLength)) {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }

    dirPathLength = (size_t)GetModuleFileName(module, sysFilePath, MAX_PATH);
    if (dirPathLength == 0) {
        return false;
    }
    for (; dirPathLength > 0 && sysFilePath[dirPathLength] != L'\\'; dirPathLength--)
        ;
    if (sysFilePath[dirPathLength] != L'\\' || dirPathLength + sysFilenameLength + 1 >= MAX_PATH) {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }

    if (!pmStrCpy(sysFilePath + dirPathLength + 1, MAX_PATH - dirPathLength - 1, PORTMASTER_DRIVER_NAME)) {
        SetLastError(ERROR_BAD_PATHNAME);
        return false;
    }

    return true;
}

static SC_HANDLE portmasterDriverInstall(const char* portmasterKextPath) {
    DWORD err = 0;
    DWORD retries = 2;
    wchar_t pmSys[MAX_PATH+1];
    SC_HANDLE service = NULL;
    

    // Open the service manager:
    SC_HANDLE manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL) {
        goto pmDriverInstallExit;
    }

    // Check if the portmaster service already exists; if so, start it.
pmDriverInstallReTry:
    service = OpenService(manager, PORTMASTER_DEVICE_NAME, SERVICE_ALL_ACCESS);
    if (service != NULL) {
        goto pmDriverInstallExit;
    }

    // Get driver file:
    if (portmasterKextPath == NULL) {
        INFO("Getting default name for portmaster kext");
        if (!getDriverFileName(pmSys)) {
            goto pmDriverInstallExit;
        }
    } else {
        if (strlen(portmasterKextPath) >= MAX_PATH) {
            ERR("portmaster_kext_path too long: %s", portmasterKextPath);
            SetLastError(ERROR_BAD_LENGTH);
            goto pmDriverInstallExit;
        }
        
        // FIXME: error C4996: 'mbstowcs': This function or variable may be unsafe. Consider using mbstowcs_s instead. To disable deprecation, use _CRT_SECURE_NO_WARNINGS.
        mbstowcs(pmSys, portmasterKextPath, MAX_PATH);
    }
    INFO("Trying to start Service '%ls'", pmSys);

    // Create the service:
    service = CreateService(manager, PORTMASTER_DEVICE_NAME,
            PORTMASTER_DEVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, pmSys, NULL, NULL,
            NULL, NULL, NULL);
    if (service == NULL) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            if (retries != 0) {
                retries--;
                goto pmDriverInstallReTry;
            }
        }
        goto pmDriverInstallExit;
    }

pmDriverInstallExit:

    if (service != NULL) {
        // Start the service:
        if (!StartService(service, 0, NULL)) {
            err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) {
                SetLastError(0);
            } else {
                // Failed to start service; clean-up:
                SERVICE_STATUS status;
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                DeleteService(service);
                CloseServiceHandle(service);
                service = NULL;
                SetLastError(err);
            }
        }
    }

    err = GetLastError();
    if (manager != NULL) {
        CloseServiceHandle(manager);
    }
    SetLastError(err);

    return service;
}

/*
 * Open a portmaster_kernel handle.
 */
HANDLE portmasterKernelOpen(const char* portmasterKextPath) {
#define FORMAT_FLAGS FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER
    DWORD err = 0;
    LPCTSTR strErrorMessage = NULL;

    INFO("Trying to CreateFile %ls", L"\\\\.\\" PORTMASTER_DEVICE_NAME);
    HANDLE handle = CreateFile( L"\\\\.\\" PORTMASTER_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    INFO("portmasterKernelOpen value of handle (*void) == 0xp%p", handle);
    if (handle == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        FormatMessage(FORMAT_FLAGS, NULL, err, 0, (LPWSTR) &strErrorMessage, 0, NULL);
        WARN("portmasterKernelOpen handle invalid: err= %u", err);
        WARN("portmasterKernelOpen %ls", strErrorMessage);
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
            ERR("portmasterKernelOpen err= %u is unhandled -> exit", err);
            return INVALID_HANDLE_VALUE;
        }

        // Open failed because the device isn't installed; install it now.
        WARN("portmasterKernelOpen CreateFile: ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND -> device not installed, install it now");
        SetLastError(0);
        SC_HANDLE service = portmasterDriverInstall(portmasterKextPath);
        if (service == NULL) {
            err= GetLastError();
            if (err == 0) {
                ERR("portmasterKernelOpen device install NOK: err was %u but service NOT installed (why?)", err);
                FormatMessage(FORMAT_FLAGS, NULL, err, 0, (LPWSTR) &strErrorMessage, 0, NULL);
                WARN("portmasterKernelOpen device install NOK: ls%u", strErrorMessage);
                SetLastError(ERROR_OPEN_FAILED);
            }
            return INVALID_HANDLE_VALUE;
        }
        INFO("portmasterKernelOpen device install OK -> service running (test with sc query portmaster_kernel)!");

        handle = CreateFile(L"\\\\.\\" PORTMASTER_DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                INVALID_HANDLE_VALUE);

        //Schedule the service to be deleted (once all handles are closed).
        //This does not seem to work.  Stop service with
        //sc stop portmaster_kernel
        DeleteService(service);
        CloseServiceHandle(service);

        if (handle == INVALID_HANDLE_VALUE) {
            err= GetLastError();
            INFO("portmasterKernelOpen CreateFile NOK: handle=0x%p, err=%u", handle, err);
            FormatMessage(FORMAT_FLAGS, NULL, err, 0, (LPWSTR) &strErrorMessage, 0, NULL);
            WARN("portmasterKernelOpen %ls", strErrorMessage);
            return INVALID_HANDLE_VALUE;
        }
    }
    return handle;
}

bool pmStrLen(const wchar_t *s, size_t maxlen, size_t *lengthPtr) {
    size_t i;
    for (i = 0; s[i]; i++) {
        if (i > maxlen) {
            return false;
        }
    }
    *lengthPtr = i;
    return true;
}

bool pmStrCpy(wchar_t *dst, size_t dstlen, const wchar_t *src) {
    size_t i;
    for (i = 0; src[i]; i++) {
        if (i > dstlen) {
            return false;
        }
        dst[i] = src[i];
    }
    if (i > dstlen) {
        return false;
    }
    dst[i] = src[i];
    return true;
}
