/*
 *  Name:        pm_api.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declation of API for the Safing Portmaster
 *               This dll does not log to a text file, except in debug mode.
 *               Error Handling is done with return values, which must be
 *               handled by the calling application.
 *               Exported functions are defined in "pm_api.def"
 *
 *  Credits:     Based on the excellent work of
 *                   Jared Wright, https://github.com/JaredWright/WFPStarterKit
 *                   Basil, https://github.com/basil00/Divert
 *
 *  Scope:       Userland
 */


#ifndef __PORTMASTER_H
#define __PORTMASTER_H

#ifndef _EXPORT
#define _EXPORT     __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************/
/* Portmaster API                                                           */
/****************************************************************************/

/*
 * Internal initialization for the kernel extension.
 */
extern _EXPORT int PortmasterInit();

/*
 * Start intercepting packets.  This is called once when Portmaster starts
 *
 * portmaster_kext_path: full path to portmaster kernel extension (e.g. "c:\windows\system32\drivers\pm_kernel64.sys")
 *                       if NULL, default name and working directory will be used
 *
 * returns: ERROR_SUCCESS:             SUCCESS
 *          ERROR_FILE_NOT_FOUND:      path is invalid
 *          Windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT int PortmasterStart(__in const char* portmaster_kext_path);

/*
 * Stops the driver and unloads the kernel driver, which runs as a service
 *
 * returns: ERROR_SUCCESS:   SUCCESS
 *          windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT int PortmasterStop();

/*
 * "Blocks" the application till unknown packet is received.
 * Returns the packet and expectes the application to return a verdict,
 * like accept, block, drop, permanentAccept ...
 *
 * packet_info: packet meta data
 *
 * returns: ERROR_SUCCESS:          SUCCESS
 *          ERROR_INVALID_DATA:     No Data received (e.g. Timeout)
 *          windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT int PortmasterRecvVerdictRequest(__out pportmaster_packet_info packet_info);


/*
 * Set Verdict like Accept, Block, Drop.
 * Use negative value of verdict_t to indicate temporary action for one packet.
 * Use packet_id from PortmasterRecvVerdictRequest->packet_info to identify packet.
 *
 * packet_id:  id received from  PortmasterRecvVerdictRequest-> packet_info.id
 * verdict:     verdict as defined in pm_common.h: PORTMASTER_VERDICT_*
 *              Permanent Verdicts use the defines,
 *              Temporary Verdicts (valid for this only packet) negate the value of the defines (* -1)
 *
 * returns: ERROR_SUCCESS:   SUCCESS
 *          windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT int PortmasterSetVerdict(__in UINT32 packet_id, __in verdict_t verdict);

/*
 * Get Payload of packet_id
 *
 * packet_id: same as received from PortmasterRecvVerdictRequest
 * buf:         Caller supplied storage of payload
 * len:         Max size of payload -> should be read from pportmaster_packet_info.packetSize
 *              Will be set according to acutal lenght in Kernel
 *
 * returns: ERROR_SUCCESS:             SUCCESS
            ERROR_NO_SYSTEM_RESOURCES: if usersupplied buffer for packet is too small (may be derived from NT_STATUS 'STATUS_INSUFFICIENT_RESOURCES')
            ERROR_FILE_NOT_FOUND:      if packet id is not found in kernel packet cache (may be derived from NT_STATUS 'STATUS_OBJECT_NAME_NOT_FOUND')
            any GetLastError():        in case of unsuccessful communication with kernel (DeviceIoControl)
 */
extern _EXPORT UINT32 PortmasterGetPayload(__in UINT32 packet_id, __out UINT8* buf, __inout UINT32* len);

/*
 * Get Reset connection cache
 *
 * returns: ERROR_SUCCESS:             SUCCESS
            any GetLastError():        in case of unsuccessful communication with kernel (DeviceIoControl)
 */
extern _EXPORT int PortmasterClearCache();

#ifdef __cplusplus
}
#endif

#endif      /* __PORTMASTER_H */
