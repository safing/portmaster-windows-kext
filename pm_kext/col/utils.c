/*
 *  Name:        utils.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utilities for packet and verdict cache.
 *
 *  Scope:       Kernelmode
 *               (Userland for development)
 */

#include <stdlib.h>

#include "pm_kernel.h"
#include "pm_utils.h"

/**
 * @brief Compares two PORTMASTER_PACKET_INFO for full equality
 *
 * @par    a  = PORTMASTER_PACKET_INFO to compare
 * @par    b  = PORTMASTER_PACKET_INFO to compare
 * @return equality (bool as int)
 *
 */
int compare_full_packet_info(pportmaster_packet_info  a, pportmaster_packet_info  b) {
    int i;

    // IP#, Protocol
    if (a->ipV6 != b->ipV6) {
        return FALSE;
    }
    if (a->protocol != b->protocol) {
        return FALSE;
    }

    // Ports
    if (a->localPort != b->localPort) {
        return FALSE;
    }
    if (a->remotePort != b->remotePort) {
        return FALSE;
    }

    // IPs
    for (i = 0; i < 4; i++) {
        if (a->localIP[i] != b->localIP[i]) {
            return FALSE;
        }
        if (a->remoteIP[i] != b->remoteIP[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Compares two PORTMASTER_PACKET_INFO for local adress equality
 *
 * @par    original  = original PORTMASTER_PACKET_INFO to compare
 * @par    current   = new (of current packet) PORTMASTER_PACKET_INFO to compare
 * @return equality (bool as int)
 *
 */
int compare_reverse_redir_packet_info(pportmaster_packet_info original, pportmaster_packet_info current) {
    int i;

    // IP#, Protocol
    if (original->ipV6 != current->ipV6) {
        return FALSE;
    }
    if (original->protocol != current->protocol) {
        return FALSE;
    }

    // Ports
    if (original->localPort != current->localPort) {
        return FALSE;
    }

    // IPs
    for (i = 0; i < 4; i++) {
        if (original->localIP[i] != current->localIP[i]) {
            return FALSE;
        }
    }

    // check local original IP (that we DNAT to) against the new remote IP
    // this is always the case for returning DNATed packets
    for (i = 0; i < 4; i++) {
        if (original->localIP[i] != current->remoteIP[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Compares two PORTMASTER_PACKET_INFO for remote address equality
 *
 * @par    a  = PORTMASTER_PACKET_INFO to compare
 * @par    b  = PORTMASTER_PACKET_INFO to compare
 * @return equality (bool as int)
 *
 */
int compare_remote_packet_info(pportmaster_packet_info  a, pportmaster_packet_info  b) {
    int i;

    // IP#, Protocol
    if (a->ipV6 != b->ipV6) {
        return FALSE;
    }
    if (a->protocol != b->protocol) {
        return FALSE;
    }

    // Ports
    if (a->remotePort != b->remotePort) {
        return FALSE;
    }

    // IPs
    for (i = 0; i < 4; i++) {
        if (a->remoteIP[i] != b->remoteIP[i]) {
            return FALSE;
        }
    }

    return TRUE;
}
