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
#define DEBUG_ON		// Undefine if Debug Functions should not be compiled
/****************************************************************************/

#define DEBUG_BUFSIZE       256		
#define LEVEL_DEBUG 0
#define LEVEL_INFO  1
#define LEVEL_WARN  2
#define LEVEL_ERROR 3

#ifndef LOGGER_NAME
	#define LOGGER_NAME "pm_default"
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
    #define DEBUG(...)  _DEBUG(0, ##__VA_ARGS__)
    #define INFO(...)   _DEBUG(1, ##__VA_ARGS__)
    #define WARN(...)   _DEBUG(2, ##__VA_ARGS__)
    #define ERR(...)  _DEBUG(3, ##__VA_ARGS__)        //ERROR is already defined in wingdi.h

    #define _DEBUG(level, format, ...) __DEBUG(LOGGER_NAME, level, __LINE__, format, ##__VA_ARGS__)
    extern void __DEBUG(char* name, int level, int line, char* format, ...);
    extern void print_ip_header(char* buf, unsigned long buf_len, char* data, unsigned long data_len);
    extern char* print_ipv4_packet(void* packet);
    extern char* print_packet_info(pportmaster_packet_info packetInfo);
    extern void initDebugStructure();
    
#else
    #define DEBUG(...)  {}
    #define INFO(...)   {}
    #define WARN(...)   {}
    #define ERR(...)    {} 
    
    #define print_ip_header   {}
    #define print_ipv4_packet {}
    #define print_packet_info {}
    #define initDebugStructure() {}
#endif

#define FORMAT_ADDR(x) (x>>24)&0xFF, (x>>16)&0xFF, (x>>8)&0xFF, x&0xFF

#endif //Include Guard


