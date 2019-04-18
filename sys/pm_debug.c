/*
 *  Name:        pm_debug.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of debug and logging features for Portmaster
 *
 *  Scope:       Kernelmode
 */

#include "pm_kernel.h"
#include "pm_common.h"
#include "pm_debug.h"

int logLevel= LEVEL_INFO;

#ifdef DEBUG_ON
#define _BUILD "DEBUG"

void __DEBUG(char* name, int level, int line, char* format, ...) {
    if (level >= logLevel) {
        va_list args;
        static char buf[DEBUG_BUFSIZE+1];
        static char *level_names[]= {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
        va_start(args, format);
        RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);

        DbgPrint("%s %s L%04d: %s\n", name, level_names[level], line, buf);
        va_end(args);
    }
}

void ipToString(int *ip, BOOL ipV6, char* buf, int size) {
    if(ipV6) {
        RtlStringCbPrintfA(buf, size, "%08x:%08x:%08x:%08x", ip[0], ip[1], ip[2], ip[3]);
    } else {
        int a,b,c,d;
        a= (ip[0] >> 24) & 0xff;
        b= (ip[0] >> 16) & 0xff;
        c= (ip[0] >> 8) & 0xff ;
        d= ip[0] & 0xff;
        RtlStringCbPrintfA(buf, size, "%u.%u.%u.%u", d, c, b, a);
    }
    return;
}

void print_ip_header(char* buf, unsigned long buf_len, char* data, unsigned long data_len) {
    unsigned long current_pos, i;
    current_pos= 0;
    i= 0;
    RtlStringCbPrintfA(buf, 250, "%3u %3u %3u %3u", data[i]& 0xFF, data[i+1]& 0xFF, data[i+2]& 0xFF, data[i+3]& 0xFF);
    return;
    for (i= 0; i < data_len; i++) {
        current_pos= i*3;
        if (current_pos >= (buf_len-3)) {
            RtlStringCbPrintfA(buf+current_pos-3, 3, "%3s", "...");
            buf[buf_len -1]= 0;
            return;
        }
        RtlStringCbPrintfA(buf+current_pos, 3, "%3u %3u %3u %3u", data[i]& 0xFF, data[i+1]& 0xFF, data[i+2]& 0xFF, data[i+3]& 0xFF);
        buf[buf_len -1]= 0;
    }
    return;
}


char* print_ipv4_packet(void* packet) {
    static char buf[256]; //this is NOT threadsafe but quick.
    PIPV4_HEADER p= (PIPV4_HEADER) packet;

    RtlStringCbPrintfA(buf, sizeof(buf), "ipv4 packet Ver=%d, Prot=%d, Check=0x%02x  Src=%d.%d.%d.%d, Dst=%d.%d.%d.%d",
        p->Version,
        p->Protocol,
        p->Checksum,
        FORMAT_ADDR(RtlUlongByteSwap(p->SrcAddr)),
        FORMAT_ADDR(RtlUlongByteSwap(p->DstAddr)));

    return buf;
}

char* print_packet_info(pportmaster_packet_info packetInfo) {
    static char buf[512];  //this is NOT threadsafe but quick.

    if (packetInfo->ipV6 == 1) {
        RtlStringCbPrintfA(buf, sizeof(buf), "[%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X]:%hu --> [%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X]:%hu",
            FORMAT_ADDR(packetInfo->localIP[0]),
            FORMAT_ADDR(packetInfo->localIP[1]),
            FORMAT_ADDR(packetInfo->localIP[2]),
            FORMAT_ADDR(packetInfo->localIP[3]),
            packetInfo->localPort,
            FORMAT_ADDR(packetInfo->remoteIP[0]),
            FORMAT_ADDR(packetInfo->remoteIP[1]),
            FORMAT_ADDR(packetInfo->remoteIP[2]),
            FORMAT_ADDR(packetInfo->remoteIP[3]),
            packetInfo->remotePort);
    } else {
        RtlStringCbPrintfA(buf, sizeof(buf), "%d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu",
            FORMAT_ADDR(packetInfo->localIP[0]), packetInfo->localPort, FORMAT_ADDR(packetInfo->remoteIP[0]), packetInfo->remotePort);
    }
    return buf;
}




#else       // DEBUG_ON
#define _BUILD "RELEASE"
#define __DEBUG(format, ...)
#endif
