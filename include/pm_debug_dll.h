/*
 *  Name:		 pm_debug_dll.h
 *
 *  Owner:		 Safing ICS Technologies GmbH
 *
 *  Description: Defines protoypes for Debug Functions, which are only 
 *               available in dll
 *
 *  Scope:       Userland
 */


#ifndef __PORTMASTER_HELPER_H
#define __PORTMASTER_HELPER_H

/****************************************************************************/
/* Portmaster Helper Prototypes                                             */
/****************************************************************************/
#ifdef DEBUG_ON
    extern pportmaster_packet_info createIPv4PacketInfo(pportmaster_packet_info packet_info);
    extern pportmaster_packet_info createIPv6PacketInfo1(pportmaster_packet_info packet_info);
    extern pportmaster_packet_info createIPv6PacketInfo2(pportmaster_packet_info packet_info);
    extern void packetToString(pportmaster_packet_info packet_info);	

#else
    #define createIPv4PacketInfo(...)   {}
    #define createIPv6PacketInfo1(...)  {}
    #define createIPv6PacketInfo2(...)  {}
    #define packetToString(...)         {}
#endif

/****************************************************************************/
/* Debugging  API -> defined in pm_debug.h (for kernel AND DLL)             */
/****************************************************************************/

#endif	
	
	
