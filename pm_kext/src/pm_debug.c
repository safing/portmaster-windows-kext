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

int logLevel = LEVEL_INFO;

#ifdef DEBUG_ON
#define _BUILD "DEBUG"

static KSPIN_LOCK debugLock;

void __DEBUG(char* name, int level, int line, char* format, ...) {
    if (level >= logLevel) {
        KLOCK_QUEUE_HANDLE lockHandle;
        //Locking is required because we want to use static variables here for better performance
        KeAcquireInStackQueuedSpinLock(&debugLock, &lockHandle);
        {
            va_list args;
            static char buf[DEBUG_BUFSIZE + 1];
            static char *levelNames[] = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
            va_start(args, format);
            RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);

            DbgPrint("%s %s L%04d: %s\n", name, levelNames[level], line, buf);
            va_end(args);
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }
}

void ipToString(int *ip, bool ipV6, char* buf, int size) {
    if(ipV6) {
        RtlStringCbPrintfA(buf, size, "%08x:%08x:%08x:%08x", ip[0], ip[1], ip[2], ip[3]);
    } else {
        UINT8 a,b,c,d;
        a = (UINT8)((ip[0] >> 24) & 0xff);
        b = (UINT8)((ip[0] >> 16) & 0xff);
        c = (UINT8)((ip[0] >> 8) & 0xff);
        d = (UINT8)(ip[0] & 0xff);
        RtlStringCbPrintfA(buf, size, "%u.%u.%u.%u", d, c, b, a);
    }
    return;
}

void printIpHeader(char* buf, unsigned long bufLength, char* data, unsigned long dataLength) {
    UNREFERENCED_PARAMETER(dataLength);
    UNREFERENCED_PARAMETER(bufLength);
    size_t i = 0;
    RtlStringCbPrintfA(buf, 250, "%3u %3u %3u %3u", (UINT8)(data[i]& 0xFF), (UINT8)(data[i+1]& 0xFF), (UINT8)(data[i+2]& 0xFF), (UINT8)(data[i+3]& 0xFF));
    /* for (i = 0; i < dataLength; i++) {
        currentPos= i * 3;
        if (currentPos >= (bufLength - 3)) {
            RtlStringCbPrintfA(buf + currentPos - 3, 3, "%3s", "...");
            buf[bufLength - 1]= 0;
            return;
        }
        RtlStringCbPrintfA(buf + currentPos, 3, "%3u %3u %3u %3u", data[i]& 0xFF, data[i+1]& 0xFF, data[i+2]& 0xFF, data[i+3]& 0xFF);
        buf[bufLength - 1]= 0;
    }*/
}


char* printIpv4Packet(void* packet) {
    static char buf[256]; // this is NOT threadsafe but quick.
    IPv4Header *p = (IPv4Header*) packet;

    RtlStringCbPrintfA(buf, sizeof(buf), "ipv4 packet Ver=%ud, Prot=%ud, Check=0x%02x  Src=%d.%d.%d.%d, Dst=%d.%d.%d.%d",
        p->Version,
        p->Protocol,
        p->Checksum,
        FORMAT_ADDR(RtlUlongByteSwap(p->SrcAddr)),
        FORMAT_ADDR(RtlUlongByteSwap(p->DstAddr)));

    return buf;
}

char* printPacketInfo(PortmasterPacketInfo *packetInfo) {
    static char buf[512];  //this is NOT threadsafe but quick.

    if (packetInfo->ipV6 == 1) {
        RtlStringCbPrintfA(buf, sizeof(buf), "[%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X]:%hu <-%ud-> [%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X:%X%02X]:%hu",
            FORMAT_ADDR(packetInfo->localIP[0]),
            FORMAT_ADDR(packetInfo->localIP[1]),
            FORMAT_ADDR(packetInfo->localIP[2]),
            FORMAT_ADDR(packetInfo->localIP[3]),
            packetInfo->localPort,
            packetInfo->direction,
            FORMAT_ADDR(packetInfo->remoteIP[0]),
            FORMAT_ADDR(packetInfo->remoteIP[1]),
            FORMAT_ADDR(packetInfo->remoteIP[2]),
            FORMAT_ADDR(packetInfo->remoteIP[3]),
            packetInfo->remotePort);
    } else {
        RtlStringCbPrintfA(buf, sizeof(buf), "%d.%d.%d.%d:%hu <-%ud-> %d.%d.%d.%d:%hu",
            FORMAT_ADDR(packetInfo->localIP[0]),
            packetInfo->localPort,
            packetInfo->direction,
            FORMAT_ADDR(packetInfo->remoteIP[0]),
            packetInfo->remotePort);
    }
    return buf;
}

void initDebugStructure()
{
    KeInitializeSpinLock(&debugLock);
}


#else       // DEBUG_ON
#define _BUILD "RELEASE"
#define __DEBUG(format, ...)
#endif
