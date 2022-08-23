/*
 *  Name:		 verdict_test.c
 *
 *  Owner:		 Safing ICS Technologies GmbH
 *
 *  Description: Contains test application for verdict cache.
 *
 *  Scope:       Userland for development purpose
 */

#include <stdio.h>
#include <stdlib.h>

#include "../include/verdict_cache.h"


int main() {

  // create
  verdict_cache_t* verdict_cache;
  int rc = create_verdict_cache(256, &verdict_cache);
  if (rc != 0) {
    fprintf(stderr, "failed to init verdict cache\n");
    return rc;
  }

  // test structs
  void* packet;
  packet = calloc(sizeof(1), 1);

  // put 1
  PORTMASTER_PACKET_INFO* packet_info1;
  packet_info1 = calloc(sizeof(PORTMASTER_PACKET_INFO), 1);
  packet_info1->protocol = 1;
  rc = add_verdict(verdict_cache, packet_info1, PORTMASTER_VERDICT_DROP);
  if (rc != 0) {
    fprintf(stderr, "failed to add verdict: return code %d\n", rc);
    return rc;
  }

  // put 2
  PORTMASTER_PACKET_INFO* packet_info2;
  packet_info2 = calloc(sizeof(PORTMASTER_PACKET_INFO), 2);
  packet_info2->protocol = 2;
  rc = add_verdict(verdict_cache, packet_info2, PORTMASTER_VERDICT_BLOCK);
  if (rc != 0) {
    fprintf(stderr, "failed to add verdict: return code %d\n", rc);
    return rc;
  }

  // put 3
  PORTMASTER_PACKET_INFO* packet_info3;
  packet_info3 = calloc(sizeof(PORTMASTER_PACKET_INFO), 3);
  packet_info3->protocol = 3;
  rc = add_verdict(verdict_cache, packet_info3, PORTMASTER_VERDICT_ACCEPT);
  if (rc != 0) {
    fprintf(stderr, "failed to add verdict: return code %d\n", rc);
    return rc;
  }

  // test return value
  verdict_t rv_verdict;

  // check 2
  rc = check_verdict(verdict_cache, packet_info2, &rv_verdict);
  if (rc != 0) {
    fprintf(stderr, "failed to check verdict #2\n");
    return rc;
  }
  if (rv_verdict != PORTMASTER_VERDICT_BLOCK) {
    fprintf(stderr, "got unexpected verdict for #2\n");
    return 1;
  }
  fprintf(stderr, "retrieved verdict 2\n");
  fprintf(stderr, "verdict_cache size: %lu\n", verdict_cache->size);

  // check 3
  rc = check_verdict(verdict_cache, packet_info3, &rv_verdict);
  if (rc != 0) {
    fprintf(stderr, "failed to check verdict #3\n");
    return rc;
  }
  if (rv_verdict != PORTMASTER_VERDICT_ACCEPT) {
    fprintf(stderr, "got unexpected verdict for #3\n");
    return 1;
  }
  fprintf(stderr, "retrieved verdict 3\n");
  fprintf(stderr, "verdict_cache size: %lu\n", verdict_cache->size);

  // check 1
  rc = check_verdict(verdict_cache, packet_info1, &rv_verdict);
  if (rc != 0) {
    fprintf(stderr, "failed to check verdict #1\n");
    return rc;
  }
  if (rv_verdict != PORTMASTER_VERDICT_DROP) {
    fprintf(stderr, "got unexpected verdict for #1\n");
    return 1;
  }
  fprintf(stderr, "retrieved verdict 1\n");
  fprintf(stderr, "verdict_cache size: %lu\n", verdict_cache->size);

  // clean up
  free(packet_info1);
  free(packet_info2);
  free(packet_info3);
  rc = teardown_verdict_cache(verdict_cache);
  if (rc != 0) {
    fprintf(stderr, "failed to tear down\n");
    return rc;
  }

  // success
  fprintf(stderr, "verdict_cache tests succeeded\n");
  return 0;
}
