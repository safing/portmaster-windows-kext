/*
 *  Name:        pm_api.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declaration of API for the Safing Portmaster
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
#define _EXPORT     __declspec(dllexport)
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
extern _EXPORT UINT32 PortmasterInit();

/*
 * Start intercepting packets.  This is called once when Portmaster starts
 *
 * portmasterKextPath: full path to portmaster kernel extension (e.g. "c:\windows\system32\drivers\pm_kernel64.sys")
 *                       if NULL, default name and working directory will be used
 *
 * returns: ERROR_SUCCESS:             SUCCESS
 *          ERROR_FILE_NOT_FOUND:      path is invalid
 *          Windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT UINT32 PortmasterStart(__in const char *portmasterKextPath);

/*
 * Stops the driver and unloads the kernel driver, which runs as a service
 *
 * returns: ERROR_SUCCESS:   SUCCESS
 *          windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT UINT32 PortmasterStop();

/*
 * "Blocks" the application till unknown packet is received.
 * Returns the packet and expects the application to return a verdict,
 * like accept, block, drop, permanentAccept ...
 *
 * packetInfo: packet meta data
 *
 * returns: ERROR_SUCCESS:          SUCCESS
 *          ERROR_INVALID_DATA:     No Data received (e.g. Timeout)
 *          windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT UINT32 PortmasterRecvVerdictRequest(__out PortmasterPacketInfo *packetInfo);


/*
 * Set Verdict like Accept, Block, Drop.
 * Use negative value of verdict_t to indicate temporary action for one packet.
 * Use packetID from PortmasterRecvVerdictRequest->packetInfo to identify packet.
 *
 * packetID:  id received from  PortmasterRecvVerdictRequest-> packetInfo.id
 * verdict:     verdict as defined in pm_common.h: PORTMASTER_VERDICT_*
 *              Permanent Verdicts use the defines,
 *              Temporary Verdicts (valid for this only packet) negate the value of the defines (* -1)
 *
 * returns: ERROR_SUCCESS:   SUCCESS
 *          windows System Error Code: according to https://docs.microsoft.com/en-us/windows/desktop/Debug/system-error-codes
 */
extern _EXPORT UINT32 PortmasterSetVerdict(__in UINT32 packetID, __in verdict_t verdict);

/*
 * Get Payload of packetID
 *
 * packetID: same as received from PortmasterRecvVerdictRequest
 * buf:         Caller supplied storage of payload
 * len:         Max size of payload -> should be read from PPortmasterPacketInfo.packetSize
 *              Will be set according to actual length in Kernel
 *
 * returns: ERROR_SUCCESS:             SUCCESS
            ERROR_NO_SYSTEM_RESOURCES: if user supplied buffer for packet is too small (may be derived from NT_STATUS 'STATUS_INSUFFICIENT_RESOURCES')
            ERROR_FILE_NOT_FOUND:      if packet id is not found in kernel packet cache (may be derived from NT_STATUS 'STATUS_OBJECT_NAME_NOT_FOUND')
            any GetLastError():        in case of unsuccessful communication with kernel (DeviceIoControl)
 */
extern _EXPORT UINT32 PortmasterGetPayload(__in UINT32 packetID, __out UINT8* buf, __inout UINT32* len);

/*
 * Get Reset connection cache
 *
 * returns: ERROR_SUCCESS:             on success
            any GetLastError():        in case of unsuccessful communication with kernel (DeviceIoControl)
 */
extern _EXPORT UINT32 PortmasterClearCache();

#ifdef __cplusplus
}
#endif

#endif      /* __PORTMASTER_H */
