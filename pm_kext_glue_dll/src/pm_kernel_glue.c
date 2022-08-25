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
static SC_HANDLE portmasterDriverInstall(const char* portmaster_kext_path);

/*
 * Thread local.
 */
static DWORD portmaster_tls_idx;

/*
 * Current DLL hmodule.
 */
static HMODULE module = NULL;

/*
 * Dll Entry
 */
extern BOOL APIENTRY portmasterDllEntry(HANDLE module0, DWORD reason, LPVOID reserved) {
    HANDLE event;
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            module = module0;
            if ((portmaster_tls_idx = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
                return FALSE;
            }
        // Fallthrough
        case DLL_THREAD_ATTACH:
            event = CreateEvent(NULL, FALSE, FALSE, NULL);
            if (event == NULL) {
                return FALSE;
            }
            TlsSetValue(portmaster_tls_idx, (LPVOID)event);
            break;

        case DLL_PROCESS_DETACH:
            event = (HANDLE)TlsGetValue(portmaster_tls_idx);
            if (event != (HANDLE)NULL) {
                CloseHandle(event);
            }
            TlsFree(portmaster_tls_idx);
            break;

        case DLL_THREAD_DETACH:
            event = (HANDLE)TlsGetValue(portmaster_tls_idx);
            if (event != (HANDLE)NULL) {
                CloseHandle(event);
            }
            break;
    }
    return TRUE;
}


/*
 * Locate the portmaster driver files and copy filename with path to sys_str
 */
static BOOLEAN getDriverFileName(LPWSTR sys_str) {
    size_t dir_len, sys_len;

    if (!pmStrLen(PORTMASTER_DRIVER_NAME, MAX_PATH, &sys_len)) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    dir_len= (size_t)GetModuleFileName(module, sys_str, MAX_PATH);
    if (dir_len == 0) {
        return FALSE;
    }
    for (; dir_len > 0 && sys_str[dir_len] != L'\\'; dir_len--)
        ;
    if (sys_str[dir_len] != L'\\' || dir_len + sys_len + 1 >= MAX_PATH) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    if (!pmStrCpy(sys_str + dir_len +1, MAX_PATH-dir_len-1, PORTMASTER_DRIVER_NAME)) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    return TRUE;
}

static SC_HANDLE portmasterDriverInstall(const char* portmaster_kext_path) {
    DWORD err, retries = 2;
    SC_HANDLE manager = NULL, service = NULL;
    wchar_t pm_sys[MAX_PATH+1];
    SERVICE_STATUS status;

    // Open the service manager:
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
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
    if (portmaster_kext_path == NULL) {
        INFO("Getting default name for portmaster kext");
        if (!getDriverFileName(pm_sys)) {
            goto pmDriverInstallExit;
        }
    } else {
        if (strlen(portmaster_kext_path) >= MAX_PATH) {
            ERR("portmaster_kext_path too long: %s", portmaster_kext_path);
            SetLastError(ERROR_BAD_LENGTH);
            goto pmDriverInstallExit;
        }
        
        // FIXME: error C4996: 'mbstowcs': This function or variable may be unsafe. Consider using mbstowcs_s instead. To disable deprecation, use _CRT_SECURE_NO_WARNINGS.
        mbstowcs(pm_sys, portmaster_kext_path, MAX_PATH);
    }
    INFO("Trying to start Service '%ls'", pm_sys);

    // Create the service:
    service = CreateService(manager, PORTMASTER_DEVICE_NAME,
            PORTMASTER_DEVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, pm_sys, NULL, NULL,
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
HANDLE portmaster_kernel_open(const char* portmaster_kext_path) {
#define FORMAT_FLAGS FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER
    DWORD err;
    HANDLE handle;
    SC_HANDLE service;
    LPCTSTR strErrorMessage = NULL;

    INFO("Trying to CreateFile %ls", L"\\\\.\\" PORTMASTER_DEVICE_NAME);
    handle = CreateFile( L"\\\\.\\" PORTMASTER_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    INFO("portmaster_kernel_open value of handle (*void) == 0xp%p", handle);
    if (handle == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        FormatMessage(FORMAT_FLAGS, NULL, err, 0, (LPWSTR) &strErrorMessage, 0, NULL);
        WARN("portmaster_kernel_open handle invalid: err= %u", err);
        WARN("portmaster_kernel_open %ls", strErrorMessage);
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
            ERR("portmaster_kernel_open err= %u is unhandled -> exit", err);
            return INVALID_HANDLE_VALUE;
        }

        // Open failed because the device isn't installed; install it now.
        WARN("portmaster_kernel_open CreateFile: ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND -> device not installed, install it now");
        SetLastError(0);
        service = portmasterDriverInstall(portmaster_kext_path);
        if (service == NULL) {
            err= GetLastError();
            if (err == 0) {
                ERR("portmaster_kernel_open device install NOK: err was %u but service NOT installed (why?)", err);
                FormatMessage(FORMAT_FLAGS, NULL, err, 0, (LPWSTR) &strErrorMessage, 0, NULL);
                WARN("portmaster_kernel_open device install NOK: ls%u", strErrorMessage);
                SetLastError(ERROR_OPEN_FAILED);
            }
            return INVALID_HANDLE_VALUE;
        }
        INFO("portmaster_kernel_open device install OK -> service running (test with sc query portmaster_kernel)!");

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
            INFO("portmaster_kernel_open CreateFile NOK: handle=0x%p, err=%u", handle, err);
            FormatMessage(FORMAT_FLAGS, NULL, err, 0, (LPWSTR) &strErrorMessage, 0, NULL);
            WARN("portmaster_kernel_open %ls", strErrorMessage);
            return INVALID_HANDLE_VALUE;
        }
    }
    return handle;
}



BOOLEAN pmStrLen(const wchar_t *s, size_t maxlen, size_t *lenptr) {
    size_t i;
    for (i = 0; s[i]; i++) {
        if (i > maxlen) {
            return FALSE;
        }
    }
    *lenptr = i;
    return TRUE;
}

BOOLEAN pmStrCpy(wchar_t *dst, size_t dstlen, const wchar_t *src) {
    size_t i;
    for (i = 0; src[i]; i++) {
        if (i > dstlen) {
            return FALSE;
        }
        dst[i] = src[i];
    }
    if (i > dstlen) {
        return FALSE;
    }
    dst[i] = src[i];
    return TRUE;
}
