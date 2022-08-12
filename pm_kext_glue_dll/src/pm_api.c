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
HANDLE handle;
int logLevel= LEVEL_ERROR;

/****************************************************************************/
/* Portmaster  API                                                          */
/****************************************************************************/

/*
 * Internal initialization for the kernel extension.
 * This is a dummy function, since initialization is done in PortmasterStart().
 */
extern _EXPORT int PortmasterInit() {
    int rc= 0;
    logLevel= LEVEL_ERROR;
    INFO("Portmaster Kernel Extension initialized");
    return rc;
}

/*
 * Start intercepting packets.
 */
extern _EXPORT int PortmasterStart(const char* portmaster_kext_path) {
    int rc= 0;
    handle= INVALID_HANDLE_VALUE;

    handle= portmaster_kernel_open(portmaster_kext_path);
    if (handle == INVALID_HANDLE_VALUE) {
        rc= GetLastError();
        ERR("Failed to open the device (%d)", rc);
        return rc;
    }
    INFO("OPENED and STARTED Portmaster Kernel Extension");
    return rc;
}

/*
 * Stops the Portmaster
 */
extern _EXPORT int PortmasterStop() {
    int rc= 0;

    INFO("Stopping Service now");
    rc= CloseHandle(handle);
    INFO("CloseHandle to Portmaster Kernel Extension returned= %d (nonzero is success)", rc);
    if (rc == 0)
    {
        rc= GetLastError();
        WARN("GetLastError= 0x%x", rc);
    }
    else 
    {
        rc= 0;
    }      
    system("sc stop " PORTMASTER_DEVICE_NAME_C);  //This is a question of taste, but it is a robust and solid solution
    return rc;
}

extern _EXPORT int PortmasterRecvVerdictRequest(pportmaster_packet_info packet_info) {
    int rc= 0;
    pportmaster_packet_info Ppacket_info;
    char *welcome = "NA";
    DWORD dwBytesRead = 0;
    char ReadBuffer[sizeof(portmaster_packet_info) +1] = {0};


    rc= DeviceIoControl(handle, IOCTL_RECV_VERDICT_REQ, welcome, strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
    if (rc == FALSE) {
        rc= GetLastError();
        WARN("DeviceIoControl did not succeed: GetLastError=%d, dwBytesRead=0x%X", rc, dwBytesRead);
        switch (rc) {
            default:
                WARN("Unexpected Error Code %d", rc);
                return rc;
        }
    }

    if ((rc == TRUE) && (dwBytesRead > 0)) {
        INFO("Bytes read : %d, rc= %d", dwBytesRead, rc);
        Ppacket_info= (pportmaster_packet_info)ReadBuffer;
        packetToString(Ppacket_info);
        memcpy(packet_info, Ppacket_info, sizeof(portmaster_packet_info));
        return ERROR_SUCCESS;
    } else {
        rc= GetLastError();
        WARN("DeviceIoControl returned TRUE but no bytes received, GetLastError=%d", rc);
        memset(packet_info, 0, sizeof(portmaster_packet_info));
        return ERROR_INVALID_DATA;
    }

}

extern _EXPORT int PortmasterSetVerdict(UINT32 packet_id, verdict_t verdict) {
    int rc= 0;
    portmaster_verdict_info verdict_info;
    char* verdict_info_buffer= (char*) &verdict_info;
    DWORD dwBytesRead = 0;
    char ReadBuffer[100] = {0}; //unused

    //Construct verdict_info
    verdict_info.id= packet_id;
    verdict_info.verdict= verdict;

    rc= DeviceIoControl(handle, IOCTL_SET_VERDICT, verdict_info_buffer, sizeof(portmaster_verdict_info), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
    INFO("IOCTL_SET_VERDICT returned %d", rc);
    if (rc == FALSE) {
        rc= GetLastError();
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
    int rc=0x11;
    DWORD bytesRead = 0;

    //Create struct to pass info to kernel
    portmaster_payload pp;
    pp.id= packet_id;
    pp.len= *len;

    rc= DeviceIoControl(handle, IOCTL_GET_PAYLOAD, (UINT8*) &pp, sizeof(portmaster_payload), buf, *len, &bytesRead, NULL);
    if (rc==FALSE) {
        rc= GetLastError();
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

    rc= ERROR_SUCCESS;
    *len= bytesRead;
    INFO("payload: id=%u, rc=0x%X, len=%u", packet_id, rc, *len);

    return rc;
}

extern _EXPORT int PortmasterClearCache() {
    int rc = 0;
    rc = DeviceIoControl(handle, IOCTL_CLEAR_CACHE, NULL, 0, NULL, 0, NULL, NULL);
    return rc;
}

#ifdef DEBUG_ON

/*
* Blocks the application till unknown packet is received.
* Returns the packet and expectes the application to return a verdict,
* like accept, block, drop, permanentAccept ...
*/
extern _EXPORT int PortmasterRecvVerdictRequestHello(pportmaster_packet_info packet_info) {
    int rc= 0;
    char *welcome = "Hello from userland.";
    DWORD dwBytesRead = 0;
    char ReadBuffer[50] = {0};

    DeviceIoControl(handle, IOCTL_HELLO, welcome, strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
    INFO("Message received from kerneland : %s", ReadBuffer);
    INFO("Bytes read : %d", dwBytesRead);

    return rc;
}

#else
#pragma message("Debugging functions will be disabled because of release version!")

#endif



