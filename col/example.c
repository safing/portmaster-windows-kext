/*
 *  Name:		 example.c
 *
 *  Owner:		 Safing ICS Technologies GmbH
 *
 *  Description: Contains sample program for verdict and packet cache
 *               to demonstrate usage
 *
 *  Scope:       Userland for development purpose
 */

#include <stdio.h>
#include <stdlib.h>

#include "../include/packet_cache.h"
#include "../include/verdict_cache.h"
#include "../include/pm_utils.h"

packet_cache_t* packet_cache;
verdict_cache_t* verdict_cache;

int init() {
  int rc;

  rc = create_packet_cache(256, &packet_cache);
  if (rc != 0) {
    return 1;
  }

  rc = create_verdict_cache(256, &verdict_cache);
  if (rc != 0) {
    return 1;
  }

  return 0;
}

bool reverse_redir(PORTMASTER_PACKET_INFO* packet_info) {
  // match incoming tcp and udp packets from
  // 127.0.0.1:53
  // 127.0.0.1:217
  // [::1]:53
  // [::1]:217

  if (packet_info->direction == false) {
    return false; // only inbound packets can be reverse redir (reverse DNAT)
  }

  // checking source ports implies a protocol with ports (eg. tcp, udp, ...)
  switch (packet_info->srcPort) {
    case 53:
    case 217:
      // source ports 53 and 2017
      break;
    default:
      return false;
  }

  switch (packet_info->protocol) {
    case 6:
    case 17:
      // tcp and udp
      break;
    default:
      return false;
  }

  // check if source IP is 127.0.0.1
  if (packet_info->srcIP[0] == 2130706433 &&
  packet_info->srcIP[1] == 0 &&
  packet_info->srcIP[2] == 0 &&
  packet_info->srcIP[3] == 0) {
    return true;
  }

  // check if source IP is ::1
  if (packet_info->srcIP[0] == 0 &&
  packet_info->srcIP[1] == 0 &&
  packet_info->srcIP[2] == 0 &&
  packet_info->srcIP[3] == 1) {
    return true;
  }

  return false;
}

int test_filter(PORTMASTER_PACKET_INFO* packet_info, void* packet, bool expect_match, bool expect_reverse_redir, verdict_t expected_verdict) {

  int rv;
  verdict_t verdict;

  // check if verdict already exists
  if (reverse_redir(packet_info)) {
    PORTMASTER_PACKET_INFO* redir_info;
    rv = check_reverse_redir(verdict_cache, packet_info, &verdict, &redir_info);
    // packet is inbound
    // reverse REDIR_DNS or REDIR_TUNNEL
    // redir_info holds original destination
  } else {
    if (expect_reverse_redir) {
      fprintf(stderr, "expected reverse redir for packet %u\n", packet_info->id);
      return 1;
    }

    rv = check_verdict(verdict_cache, packet_info, &verdict);
    // packet can by any direction
    // DROP, BLOCK, ACCEPT, REDIR_DNS or REDIR_TUNNEL
  }

  // REDIR_DNS: redir to 127.0.0.1:53 or [::1]:53
  // REDIR_TUNNEL: redir to 127.0.0.1:217 or [::1]:217

  if (rv == 0) {
    if (verdict != expected_verdict) {
      fprintf(stderr, "expected verdict %d for packet %u, but got %d\n", expected_verdict, packet_info->id, verdict);
      return 1;
    }
  } else {
    if (expect_match) {
      fprintf(stderr, "expected packet %u to match\n", packet_info->id);
      return 1;
    }
    // uint64_t packet_id = register_packet(packet_cache, packet_info, packet);
    register_packet(packet_cache, packet_info, packet);
  }

  return 0;
}

int main() {

  int rc = init();
  if (rc != 0) {
    return rc;
  }

  // save test data

  // test structs
  void* packet;
  packet = calloc(sizeof(1), 1);

  // put 1
  PORTMASTER_PACKET_INFO* packet_info1;
  packet_info1 = calloc(sizeof(PORTMASTER_PACKET_INFO), 1);
  packet_info1->protocol = 1;
  rc = add_verdict(verdict_cache, packet_info1, VERDICT_DROP);
  if (rc != 0) {
    fprintf(stderr, "failed to add verdict: return code %d\n", rc);
    return rc;
  }

  // put 2
  PORTMASTER_PACKET_INFO* packet_info2;
  packet_info2 = calloc(sizeof(PORTMASTER_PACKET_INFO), 2);
  packet_info2->protocol = 6;
  rc = add_verdict(verdict_cache, packet_info2, VERDICT_REDIR_DNS);
  if (rc != 0) {
    fprintf(stderr, "failed to add verdict: return code %d\n", rc);
    return rc;
  }

  // put 3
  PORTMASTER_PACKET_INFO* packet_info3;
  packet_info3 = calloc(sizeof(PORTMASTER_PACKET_INFO), 3);
  packet_info3->protocol = 17;
  rc = add_verdict(verdict_cache, packet_info3, VERDICT_REDIR_TUNNEL);
  if (rc != 0) {
    fprintf(stderr, "failed to add verdict: return code %d\n", rc);
    return rc;
  }

  // test



  return 0;
}
