/*
 *  Name:        pm_debug.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation for debug-features of portmaster-DLL
 *               Similar to kernel/debug.c
 *
 *  Scope:       Userland
 */

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <stdlib.h>

#include "pm_common.h"

#define LOGGER_NAME "PM-Helper"
#include "pm_debug.h"
#include "pm_debug_dll.h"

//logLevel= LEVEL_DEBUG;


/****************************************************************************/
/* Portmaster Helpers                                                       */
/****************************************************************************/
#ifdef DEBUG_ON
//void __DEBUG(char* name, int level, int line, char* format, ...);
void __DEBUG(char* name, int level, int line, char* format, ...) {
    if (level >= logLevel) {
        va_list args;
        static char buf[DEBUG_BUFSIZE+1];
        static char *level_names[]= {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
        va_start(args, format);
        vsnprintf(buf, DEBUG_BUFSIZE, format, args);
        fprintf(stdout, "%s %s L%04d: %s\n", LOGGER_NAME, level_names[level], line, buf);
        va_end(args);
    }
}


char* ipToString(UINT32 *ip, BOOL ipV6, char* buf, UINT32 size) {
    if(ipV6) {
        snprintf(buf, size, "%08x:%08x:%08x:%08x", ip[0], ip[1], ip[2], ip[3]);
    } else {
        UINT32 a,b,c,d;
        a= (ip[0] >> 24) & 0xff;
        b= (ip[0] >> 16) & 0xff;
        c= (ip[0] >> 8) & 0xff ;
        d= ip[0] & 0xff;
        snprintf(buf, size, "%u.%u.%u.%u", a, b, c, d);
    }
    return buf;
}

void packetToString(pportmaster_packet_info packet_info) {
    char* ips;
    char buf1[64];
    char buf2[64];
    if (packet_info->ipV6) {
        ips= "IPv6";
    } else {
        ips= "IPv4";
    }
    INFO("%s Packet Info: id: %u, proto: %u, dir: %u, \n\t srcIP: '%s' srcPort: %u\n\t dstIP: '%s' dstPort: %u\n",
        ips,
        packet_info->id,
        packet_info->protocol,
        packet_info->direction,
        ipToString(packet_info->localIP, packet_info->ipV6, buf1, sizeof(buf1)),
        packet_info->localPort,
        ipToString(packet_info->remoteIP, packet_info->ipV6, buf2, sizeof(buf2)),
        packet_info->remotePort);
}

pportmaster_packet_info createIPv4PacketInfo(pportmaster_packet_info packet_info) {
    packet_info->id= 123;
    packet_info->protocol=1;
    packet_info->ipV6=0;
    packet_info->direction=FALSE;
    packet_info->localIP[0]=0xff001001;
    packet_info->remoteIP[0]=0x0A000001;
    packet_info->localPort=61000;
    packet_info->remotePort=1;

    packetToString(packet_info);
    return packet_info;
}

pportmaster_packet_info createIPv6PacketInfo1(pportmaster_packet_info packet_info) {
    packet_info->id= 123;
    packet_info->protocol=1;
    packet_info->ipV6=1;
    packet_info->direction=FALSE;

    packet_info->localIP[0]=1;
    packet_info->localIP[1]=2;
    packet_info->localIP[2]=3;
    packet_info->localIP[3]=4;

    packet_info->remoteIP[0]=123456;
    packet_info->remoteIP[1]=123457;
    packet_info->remoteIP[2]=123458;
    packet_info->remoteIP[3]=123459;

    packet_info->localPort=61000;
    packet_info->remotePort=399;

    packetToString(packet_info);
    return packet_info;
}

pportmaster_packet_info createIPv6PacketInfo2(pportmaster_packet_info packet_info) {
    packet_info->id= 123;
    packet_info->processID= 456;
    packet_info->direction=1;
    packet_info->ipV6=1;

    packet_info->localIP[0]=1;
    packet_info->localIP[1]=2;
    packet_info->localIP[2]=3;
    packet_info->localIP[3]=4;

    packet_info->remoteIP[0]=789;
    packet_info->remoteIP[1]=123457;
    packet_info->remoteIP[2]=123458;
    packet_info->remoteIP[3]=123459;

    packet_info->localPort=61000;
    packet_info->remotePort=399;
    packet_info->protocol=8;

    packetToString(packet_info);
    return packet_info;
}

#endif







