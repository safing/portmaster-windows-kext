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
#include <stdbool.h>

#include "pm_common.h"

#define LOGGER_NAME "PM-Helper"
#include "pm_debug.h"
#include "pm_debug_dll.h"

//logLevel= LEVEL_DEBUG;


/****************************************************************************/
/* Portmaster Helpers                                                       */
/****************************************************************************/
#ifdef DEBUG_ON
void __DEBUG(char* name, int level, int line, char* format, ...) {
    if (level >= logLevel) {
        va_list args;
        static char buf[DEBUG_BUFSIZE+1];
        static char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
        va_start(args, format);
        vsnprintf(buf, DEBUG_BUFSIZE, format, args);
        fprintf(stdout, "%s %s L%04d: %s\n", LOGGER_NAME, level_names[level], line, buf);
        va_end(args);
    }
}

char* ipToString(UINT32 *ip, bool ipV6, char* buf, UINT32 size) {
    if(ipV6) {
        snprintf(buf, size, "%08x:%08x:%08x:%08x", ip[0], ip[1], ip[2], ip[3]);
    } else {
        UINT32 a,b,c,d;
        a = (ip[0] >> 24) & 0xff;
        b = (ip[0] >> 16) & 0xff;
        c = (ip[0] >> 8) & 0xff ;
        d = ip[0] & 0xff;
        snprintf(buf, size, "%u.%u.%u.%u", a, b, c, d);
    }
    return buf;
}

void packetToString(PortmasterPacketInfo *packetInfo) {
    char *ips = NULL;
    char buf1[64] = {0};
    char buf2[64] = {0};
    if (packetInfo->ipV6) {
        ips = "IPv6";
    } else {
        ips = "IPv4";
    }
    INFO("%s Packet Info: id: %u, proto: %u, dir: %u, \n\t srcIP: '%s' srcPort: %u\n\t dstIP: '%s' dstPort: %u\n",
        ips,
        packetInfo->id,
        packetInfo->protocol,
        packetInfo->direction,
        ipToString(packetInfo->localIP, packetInfo->ipV6, buf1, sizeof(buf1)),
        packetInfo->localPort,
        ipToString(packetInfo->remoteIP, packetInfo->ipV6, buf2, sizeof(buf2)),
        packetInfo->remotePort);
}

PortmasterPacketInfo *createIPv4PacketInfo(PortmasterPacketInfo *packet_info) {
    packet_info->id = 123;
    packet_info->protocol = 1;
    packet_info->ipV6 = 0;
    packet_info->direction = false;
    packet_info->localIP[0] = 0xff001001;
    packet_info->remoteIP[0] = 0x0A000001;
    packet_info->localPort = 61000;
    packet_info->remotePort = 1;

    packetToString(packet_info);
    return packet_info;
}

PortmasterPacketInfo *createIPv6PacketInfo1(PortmasterPacketInfo *packetInfo) {
    packetInfo->id = 123;
    packetInfo->protocol = 1;
    packetInfo->ipV6 = 1;
    packetInfo->direction = false;

    packetInfo->localIP[0] = 1;
    packetInfo->localIP[1] = 2;
    packetInfo->localIP[2] = 3;
    packetInfo->localIP[3] = 4;

    packetInfo->remoteIP[0] = 123456;
    packetInfo->remoteIP[1] = 123457;
    packetInfo->remoteIP[2] = 123458;
    packetInfo->remoteIP[3] = 123459;

    packetInfo->localPort = 61000;
    packetInfo->remotePort = 399;

    packetToString(packetInfo);
    return packetInfo;
}

PortmasterPacketInfo *createIPv6PacketInfo2(PortmasterPacketInfo *packetInfo) {
    packetInfo->id = 123;
    packetInfo->processID = 456;
    packetInfo->direction = 1;
    packetInfo->ipV6 = 1;

    packetInfo->localIP[0] = 1;
    packetInfo->localIP[1] = 2;
    packetInfo->localIP[2] = 3;
    packetInfo->localIP[3] = 4;

    packetInfo->remoteIP[0] = 789;
    packetInfo->remoteIP[1] = 123457;
    packetInfo->remoteIP[2] = 123458;
    packetInfo->remoteIP[3] = 123459;

    packetInfo->localPort = 61000;
    packetInfo->remotePort = 399;
    packetInfo->protocol = 8;

    packetToString(packetInfo);
    return packetInfo;
}

#endif
