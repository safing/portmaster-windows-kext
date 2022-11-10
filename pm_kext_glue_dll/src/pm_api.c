/*
 *  Name:        pm_api.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of API for the Safing Portmaster
 *               This dll does not log to a text file, except in debug mode.
 *               Error Handling is done with return values, which must be
 *               handled by the calling application.
 *               Exported functions are defined in "pm_api.def"
 *
 *  Credits:     Based on the excelent work of
 *                   Jared Wright, https://github.com/JaredWright/WFPStarterKit
 *                   Basil, https://github.com/basil00/Divert
 *
 *  Scope:       Userland
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "pm_common.h"
//Logger Definitions
#define LOGGER_NAME "PM_API"
#include "pm_debug.h"

#include "pm_kernel_glue.h"
#include "pm_api.h"

#include "pm_debug_dll.h"


/*
 * For the Portmaster Application, we only need one handle,
 * which we handle in the dll.  Portmaster Application does
 * not need to know about it.
 *
 */
HANDLE deviceHandle = INVALID_HANDLE_VALUE;
int logLevel = LEVEL_DEBUG;

/****************************************************************************/
/* Portmaster  API                                                          */
/****************************************************************************/

/*
 * Internal initialization for the kernel extension.
 * This is a dummy function, since initialization is done in PortmasterStart().
 */
extern _EXPORT UINT32 PortmasterInit() {
    INFO("Portmaster Kernel Extension initialized");
    return ERROR_SUCCESS;
}

/*
 * Start intercepting packets.
 */
extern _EXPORT UINT32 PortmasterStart(const char* portmasterKextPath) {
    deviceHandle = portmasterKernelOpen(portmasterKextPath);
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        DWORD rc = GetLastError();
        ERR("Failed to open the device (%d)", rc);
        return rc;
    }
    INFO("OPENED and STARTED Portmaster Kernel Extension");
    return ERROR_SUCCESS;
}

/*
 * Stops the Portmaster
 */
extern _EXPORT UINT32 PortmasterStop() {
    int rc = 0;

    INFO("Stopping Service now");
    bool success = CloseHandle(deviceHandle);
    INFO("CloseHandle to Portmaster Kernel Extension returned= %d (nonzero is success)", rc);
    if (!success)
    {
        UINT32 rc = GetLastError();
        WARN("GetLastError= 0x%x", rc);
    }
    system("sc stop " PORTMASTER_DEVICE_NAME_C);  //This is a question of taste, but it is a robust and solid solution
    return ERROR_SUCCESS;
}

extern _EXPORT UINT32 PortmasterRecvVerdictRequest(PortmasterPacketInfo *packetInfo) {
    // Check for verdict request
    char *welcome = "NA";
    DWORD dwBytesRead = 0;
    char ReadBuffer[sizeof(PortmasterPacketInfo) + 1] = {0};

    bool success = DeviceIoControl(deviceHandle, IOCTL_RECV_VERDICT_REQ, welcome, (DWORD)strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
    if (!success) {
        UINT32 rc = GetLastError();
        WARN("DeviceIoControl did not succeed: GetLastError=%d, dwBytesRead=0x%X", rc, dwBytesRead);
        switch (rc) {
            default:
                WARN("Unexpected Error Code %d", rc);
                return rc;
        }
    }

    // Process verdict request
    if (success && (dwBytesRead > 0)) {
        INFO("Bytes read : %d, rc = %d", dwBytesRead, success);
        PortmasterPacketInfo *PacketInfoFromDevice = (PortmasterPacketInfo*)ReadBuffer;
        packetToString(PacketInfoFromDevice);
        memcpy(packetInfo, PacketInfoFromDevice, sizeof(PortmasterPacketInfo));
        return ERROR_SUCCESS;
    } else {
        UINT32 rc = GetLastError();
        WARN("DeviceIoControl returned true but no bytes received, GetLastError=%d", rc);
        memset(packetInfo, 0, sizeof(PortmasterPacketInfo));
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

extern _EXPORT UINT32 PortmasterSetVerdict(UINT32 packet_id, verdict_t verdict) {
    PortmasterVerdictInfo verdictInfo = {0};
    char* verdictInfoBuffer = (char*) &verdictInfo;
    DWORD dwBytesRead = 0;
    char ReadBuffer[100] = {0}; //unused

    //Construct verdictInfo
    verdictInfo.id = packet_id;
    verdictInfo.verdict = verdict;

    bool success = DeviceIoControl(deviceHandle, IOCTL_SET_VERDICT, verdictInfoBuffer, sizeof(PortmasterVerdictInfo), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
    INFO("IOCTL_SET_VERDICT returned %d", success);
    if (!success) {
        UINT32 rc = GetLastError();
        WARN("DeviceIoControl did not succeed: GetLastError=%d, dwBytesRead=0x%X", rc, dwBytesRead);
        switch (rc) {
            default:
                WARN("Unexpected Error Code %d", rc);
                return rc;
        }
    }
    return ERROR_SUCCESS;
}

extern _EXPORT UINT32 PortmasterGetPayload(UINT32 packet_id, UINT8* buf, UINT32* len) {
    DWORD bytesRead = 0;

    // Create struct to pass info to kernel
    PortmasterPayload payload = {0};
    payload.id = packet_id;
    payload.len = *len;
    bool success = DeviceIoControl(deviceHandle, IOCTL_GET_PAYLOAD, (UINT8*) &payload, sizeof(PortmasterPayload), buf, *len, &bytesRead, NULL);
    if (!success) {
        UINT32 rc = GetLastError();
        WARN("DeviceIoControl did not succeed: GetLastError=%d, bytesRead=0x%X", rc, bytesRead);
        switch (rc) {
            case ERROR_NO_SYSTEM_RESOURCES:
                WARN("GetLastError '%d= ERROR_NO_SYSTEM_RESOURCES' -> NT-Status 'STATUS_INSUFFICIENT_RESOURCES'", rc);
                return rc;
            case ERROR_FILE_NOT_FOUND:
                WARN("GetLastError '%d= ERROR_FILE_NOT_FOUND' -> NT-Status 'STATUS_OBJECT_NAME_NOT_FOUND'", rc);
                return rc;
            default:
                WARN("Unexpected Error Code %d", rc);
                return rc;
        }
    }

    *len = bytesRead;
    INFO("payload: id=%u, rc=0x%X, len=%u", packet_id, success, *len);

    return ERROR_SUCCESS;
}

extern _EXPORT UINT32 PortmasterClearCache() {
    bool success = DeviceIoControl(deviceHandle, IOCTL_CLEAR_CACHE, NULL, 0, NULL, 0, NULL, NULL);
    if(!success) {
        UINT32 rc = GetLastError();
        WARN("Failed to clear cache: %d", rc);
        return rc;
    }
    return ERROR_SUCCESS;
}


#ifdef DEBUG_ON

/*
* Blocks the application till unknown packet is received.
* Returns the packet and expects the application to return a verdict,
* like accept, block, drop, permanentAccept ...
*/
extern _EXPORT UINT32 PortmasterRecvVerdictRequestHello(PortmasterPacketInfo *packetInfo) {
    int rc = 0;
    // char *welcome = "Hello from userland.";
    // DWORD dwBytesRead = 0;
    // char ReadBuffer[50] = {0};

    // DeviceIoControl(deviceHandle, IOCTL_HELLO, welcome, (DWORD)strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
    // INFO("Message received from kerneland : %s", ReadBuffer);
    // INFO("Bytes read : %d", dwBytesRead);

    return rc;
}

#else
#pragma message("Debugging functions will be disabled because of release version!")

#endif // DEBUG_ON



