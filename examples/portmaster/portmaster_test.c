/*
 *  Name:        pm_api.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Testapplication for portmaster
 *
 *  Scope:       Userland
 */


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "pm_common.h"
#include "pm_kernel_glue.h"
#include "pm_api.h"
#include "pm_debug_dll.h"

/*********************************************************************
 * DEBUG FEATURES
 *********************************************************************/
//Even in release builds, we want debug output in test applications ;-)
#define LOGGER_NAME "PM_TEST"

#define DEBUG_BUFSIZE       256
#define LEVEL_DEBUG 0
#define LEVEL_INFO  1
#define LEVEL_WARN  2
#define LEVEL_ERROR 3

#define DEBUG(...)  _DEBUG(0, ##__VA_ARGS__)
#define INFO(...)   _DEBUG(1, ##__VA_ARGS__)
#define WARN(...)   _DEBUG(2, ##__VA_ARGS__)
#define ERR(...)  _DEBUG(3, ##__VA_ARGS__)        //ERROR is already defined in wingdi.h

#define _DEBUG(level, format, ...) __DEBUG(LOGGER_NAME, level, __LINE__, format, ##__VA_ARGS__)

int logLevel= LEVEL_INFO;

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

/*********************************************************************
 * HELPERS
 *********************************************************************/
void testPayload(portmaster_packet_info packet_info) {
    UINT8* payload= NULL;
    UINT32 len= 0;
    UINT32 id= packet_info.id;
    int rc;

    //Get Packetinfo for DNS-Requests BEFORE setting verdict (otherwise packet may not be in cache anymore)
    len= packet_info.packetSize;
    if (len > MAX_PAYLOAD_SIZE) {
        WARN("Requested payload is too large: %u, max is %u", len, MAX_PAYLOAD_SIZE);
        return;
    }
    payload= malloc(len);
    if (!payload) {
        ERR("Payload could not be allocated");
        return;
    }
    //len= len -1;  //Provoke ERROR_NO_SYSTEM_RESOURCES (PM_STATUS_BUF_TOO_SMALL)
    //id= -1;       //Provoke ERROR_FILE_NOT_FOUND (PM_STATUS_ID_NOT_FOUND)

    INFO("Getting payload for id %u, expecting %u Bytes", packet_info.id, len);
    rc= PortmasterGetPayload(id, payload, &len);
    INFO("Received payload for id %u, %u/%u Bytes, status 0x%X, payload[0]= 0x%X", packet_info.id, len, packet_info.packetSize, rc, payload[0]);
    free(payload);

}

/*********************************************************************
 * MAIN
 *********************************************************************/
int __cdecl main(int argc, char **argv) {
    int rc;
    int i= 0;
    char buf[256];
    portmaster_packet_info packet_info;
    memset(&packet_info, 0, sizeof(portmaster_packet_info));

    INFO("Trying to initialize Portmaster");
    rc= PortmasterInit();
    //rc= PortmasterStart("c:\\temp\\pm_kernel64.sys");
    rc= PortmasterStart(NULL);
    if (rc != 0) {
        INFO("Could not open Portmaster Device: Error %d", rc);
        return -1;
    }
    INFO("Initialization done");

    Sleep(5000);

    //Simple demonstration of Portmaster like behavior
    while (TRUE) {
        i++;
        rc= PortmasterRecvVerdictRequest(&packet_info);
        if(rc !=0) {
            INFO("Nothing received");
            Sleep(1000);
            continue;
        }
        INFO("Message received!");
        //Analyze Packet

        // Allow any packet to and from local dns server
        if ((packet_info.remoteIP[0] == packet_info.localIP[0] && packet_info.remotePort == 53) ||
                (packet_info.localIP[0] == packet_info.remoteIP[0] && packet_info.localPort == 53)) {
            INFO("Accepting DNS Traffic to Portmaster packet_id: %u", packet_info.id);
            rc= PortmasterSetVerdict(packet_info.id, PORTMASTER_VERDICT_ACCEPT);
            continue;
        }

        testPayload(packet_info);

        switch (packet_info.remotePort) {
            case 53: { //Redirect "foreign" DNS Requests to our own DNS server
                INFO("Redirection DNS with id %u", packet_info.id);
                rc= PortmasterSetVerdict(packet_info.id, PORTMASTER_VERDICT_REDIR_DNS);
                //rc= PortmasterSetVerdict(packet_info.id, PORTMASTER_VERDICT_ACCEPT);

                break;
            }

            case 853: //TDNS (DNS over TLS)
            case 443: //Allow Connections over 443
                INFO("Allowing Connection with id %u  to Port %u", packet_info.id, packet_info.remotePort);
                rc= PortmasterSetVerdict(packet_info.id, PORTMASTER_VERDICT_ACCEPT);
                break;

            default: //Block everything else
                INFO("Allowing Connection with id %u to Port %u", packet_info.id, packet_info.remotePort);
                //rc= PortmasterSetVerdict(packet_info.id, PORTMASTER_VERDICT_BLOCK);
                rc= PortmasterSetVerdict(packet_info.id, PORTMASTER_VERDICT_ACCEPT);
                break;
        }
    } //while (TRUE)
    INFO("Shutdown");
    rc= PortmasterStop();
}
