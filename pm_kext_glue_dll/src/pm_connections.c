/*
 *  Name:        pm_connections.c
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

//#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <Windows.h>
//#include "pm_common.h"

static char *buffer = NULL;
static uint64_t bufferSize = 0;
static PortmasterConnection *connections = NULL;
static uint64_t *connectionsCount = NULL;
static uint64_t capacity = 0;

void ConnectionsInit(uint32_t initialCapacity) {
    capacity = initialCapacity;
    buffer = malloc(capacity * sizeof(PortmasterConnection) + sizeof(uint64_t));
    connectionsCount = (uint64_t*) buffer;
    *connectionsCount = 0;
    connections = (PortmasterConnection*) ((char*)buffer + sizeof(uint64_t));
}

void ConnectionsDestroy() {
    if(buffer != NULL) {
        free(buffer);
        buffer = NULL;
        connections = NULL;
        connectionsCount = NULL;
        capacity = 0;
    }
}

bool compareFullPacketInfo(PortmasterPacketInfo *a, PortmasterPacketInfo *b) {
    // IP#, Protocol
    if (a->ipV6 != b->ipV6) {
        return false;
    }
    if (a->protocol != b->protocol) {
        return false;
    }

    // Ports
    if (a->localPort != b->localPort) {
        return false;
    }
    if (a->remotePort != b->remotePort) {
        return false;
    }

    // IPs
    for (int i = 0; i < 4; i++) {
        if (a->localIP[i] != b->localIP[i]) {
            return false;
        }
        if (a->remoteIP[i] != b->remoteIP[i]) {
            return false;
        }
    }

    return true;
}

void ConnectionsAdd(PortmasterConnection connection) {
    for(size_t i = 0; i < *connectionsCount; i++) {
        if(compareFullPacketInfo(&connections[i].info, &connection.info)) {
            return;
        }
    }

    if(*connectionsCount >= capacity) {
        // Double the size
        char *newBuffer = malloc(capacity * 2 * sizeof(PortmasterConnection) + sizeof(uint64_t));
        capacity = capacity * 2;
        memcpy(newBuffer, buffer, (*connectionsCount) * sizeof(PortmasterConnection) + sizeof(uint64_t));
        free(buffer);
        buffer = newBuffer;
        connectionsCount = (uint64_t*) buffer;
        connections = (PortmasterConnection*) ((char*)buffer + sizeof(uint64_t));
    }
    connections[*connectionsCount] = connection;
    *connectionsCount += 1;
    connection.bytesReceived = 0;
    connection.bytesSend = 0;

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

void printConn() {
    HANDLE hFile = CreateFile(
      L"C:\\Dev\\stat.txt",     // Filename
      GENERIC_WRITE,          // Desired access
      FILE_SHARE_READ,        // Share mode
      NULL,                   // Security attributes
      CREATE_ALWAYS,          // Creates a new file, only if it doesn't already exist
      FILE_ATTRIBUTE_NORMAL,  // Flags and attributes
      NULL);                  // Template file handle

    if (hFile == INVALID_HANDLE_VALUE)
    {
      // Failed to open/create file
      return;
    }

    // char buf2[64] = {0};
    // sprintf(buf2, "%d", *connectionsCount);

    // DWORD bytesWritten;
    // WriteFile(
    //     hFile,            // Handle to the file
    //     buf2,  // Buffer to write
    //     strlen(buf2),   // Buffer size
    //     &bytesWritten,    // Bytes written
    //     NULL);         // Overlapped


    for(size_t i = 0; i < *connectionsCount; i++) {
        PortmasterConnection conn = connections[i];

        char buf1[64] = {0};
        char buf2[64] = {0};
        char tt[567] = {0};
        sprintf(tt, "%s:%d -- %s:%d -> send: %d, recv: %d\n",
            ipToString(conn.info.localIP, conn.info.ipV6, buf1, sizeof(buf1)),
            conn.info.localPort,
            ipToString(conn.info.remoteIP, conn.info.ipV6, buf2, sizeof(buf2)),
            conn.info.remotePort,
            (int)conn.bytesSend,
            (int)conn.bytesReceived);

            DWORD bytesWritten;
        WriteFile(
            hFile,            // Handle to the file
            tt,  // Buffer to write
            strlen(tt),   // Buffer size
            &bytesWritten,    // Bytes written
            NULL);         // Overlapped
    }
    CloseHandle(hFile);
}