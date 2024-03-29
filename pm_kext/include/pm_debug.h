/*
 *  Name:		 pm_common.h
 *
 *  Owner:		 Safing ICS Technologies GmbH
 *
 *  Description: Common Debug definitions for kernel and userland driver
 *               Defines the DEBUG_ON Symbol.
 *               If defined -> Debug Build
 *               If undefined -> Release Build
 *
 *  Scope:       Kernelmode
 *               Userland
 */

#ifndef PM_DEBUG_H
#define PM_DEBUG_H

/****************************************************************************/
// #define DEBUG_ON		// Undefine if Debug Functions should not be compiled
/****************************************************************************/

#define DEBUG_BUFSIZE       256
#define LEVEL_DEBUG 0
#define LEVEL_INFO  1
#define LEVEL_WARN  2
#define LEVEL_ERROR 3

#ifndef LOGGER_NAME
    #define LOGGER_NAME __FILE__
#endif

/*
 * These Logger Variables should be set (REDEFINED) in the including file
 */
extern int logLevel;  //must be defined in dll and kernel object


/* JCS: Improve Debug
 DEBUG("Where do we come from, %s %s", p1, p2);
 --> DEBUG(__LINE__, "Where do we come from, %s %s", p1, p2);
 Writing to file from kernel mode driver is not recommended and may
 not be supported at all:
 https://stackoverflow.com/questions/49091442/log-to-a-txt-file-from-a-windows-10-kernel-mode-driver#49243511
 All we can do is write to a dedicated debug channel and adjust the loglevel at runtime.
*/
#ifdef DEBUG_ON
    #define DEBUG(...)  DEBUG_LOG(0, ##__VA_ARGS__)
    #define INFO(...)   DEBUG_LOG(1, ##__VA_ARGS__)
    #define WARN(...)   DEBUG_LOG(2, ##__VA_ARGS__)
    #define ERR(...)    DEBUG_LOG(3, ##__VA_ARGS__)        //ERROR is already defined in wingdi.h

    #define DEBUG_LOG(level, format, ...) __DEBUG(LOGGER_NAME, level, __LINE__, format, ##__VA_ARGS__)
    void __DEBUG(char *name, int level, int line, char *format, ...);
    void printIpHeader(char *buf, unsigned long buf_len, char *data, unsigned long dataLength);
    char* printIpv4Packet(void *packet);
    char* printPacketInfo(PortmasterPacketInfo *packetInfo);
    void initDebugStructure();

#else
    #define DEBUG(...)  {}
    #define INFO(...)   {}
    #define WARN(...)   {}
    #define ERR(...)    {}

    #define printIpHeader   {}
    #define printIpv4Packet {}
    #define printPacketInfo {}
    #define initDebugStructure() {}
#endif

#define FORMAT_ADDR(x) (INT16)((x>>24)&0xFF), (INT16)((x>>16)&0xFF), (INT16)((x>>8)&0xFF), (INT16)(x&0xFF)

#endif //Include Guard
