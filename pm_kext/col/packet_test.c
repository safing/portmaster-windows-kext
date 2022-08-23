/*
 *  Name:		 packet_test.c
 *
 *  Owner:		 Safing ICS Technologies GmbH
 *
 *  Description: Testapplication for packet caches
 *
 *  Scope:       Userland for development purpose
 */

#include <stdio.h>
#include <stdlib.h>

#include "../include/packet_cache.h"


int main() {

  // create
  packet_cache_t* packet_cache;
  int rc = create_packet_cache(3, &packet_cache);
  if (rc != 0) {
    fprintf(stderr, "failed to init packet cache\n");
    return rc;
  }

  // test structs
  void* packet;
  packet = calloc(sizeof(1), 1);
  int packet_len = sizeof(1);

  // put 1
  portmaster_packet_info* packet_info1;
  packet_info1 = calloc(sizeof(portmaster_packet_info), 1);
  packet_info1->protocol = 1;
  uint64_t id1;
  id1 = register_packet(packet_cache, packet_info1, packet, packet_len);
  fprintf(stderr, "registered packet %lu\n", id1);
  if (id1 == 0) {
    fprintf(stderr, "failed to register packet\n");
    return 1;
  }

  // put 2
  portmaster_packet_info* packet_info2;
  packet_info2 = calloc(sizeof(portmaster_packet_info), 1);
  packet_info2->protocol = 2;
  uint64_t id2;
  id2 = register_packet(packet_cache, packet_info2, packet, packet_len);
  fprintf(stderr, "registered packet %lu\n", id2);
  if (id2 == 0) {
    fprintf(stderr, "failed to register packet\n");
    return 1;
  }

  // put 3
  portmaster_packet_info* packet_info3;
  packet_info3 = calloc(sizeof(portmaster_packet_info), 1);
  packet_info3->protocol = 3;
  uint64_t id3;
  id3 = register_packet(packet_cache, packet_info3, packet, packet_len);
  fprintf(stderr, "registered packet %lu\n", id3);
  if (id3 == 0) {
    fprintf(stderr, "failed to register packet\n");
    return 1;
  }

  // return values
  portmaster_packet_info* packet_info;

  // get 2
  rc = retrieve_packet(packet_cache, id2, &packet_info, &packet, &packet_len);
  if (rc != 0) {
    fprintf(stderr, "failed to retrieve packet #%lu\n", id2);
    return rc;
  }
  if (packet_info->protocol != packet_info2->protocol) {
    fprintf(stderr, "got unexpected object for packet #%lu\n", id2);
    return 1;
  }
  fprintf(stderr, "retrieved packet %lu\n", id2);
  fprintf(stderr, "packet_cache size: %lu\n", packet_cache->size);

  // get 3
  rc = retrieve_packet(packet_cache, id3, &packet_info, &packet, &packet_len);
  if (rc != 0) {
    fprintf(stderr, "failed to retrieve packet #%lu\n", id3);
    return rc;
  }
  if (packet_info->protocol != packet_info3->protocol) {
    fprintf(stderr, "got unexpected object for packet #%lu\n", id3);
    return 1;
  }
  fprintf(stderr, "retrieved packet %lu\n", id3);
  fprintf(stderr, "packet_cache size: %lu\n", packet_cache->size);

  // get 1
  rc = retrieve_packet(packet_cache, id1, &packet_info, &packet, &packet_len);
  if (rc != 0) {
    fprintf(stderr, "failed to retrieve packet #%lu\n", id1);
    return rc;
  }
  if (packet_info->protocol != packet_info1->protocol) {
    fprintf(stderr, "got unexpected object for packet #%lu\n", id1);
    return 1;
  }
  fprintf(stderr, "retrieved packet %lu\n", id1);
  fprintf(stderr, "packet_cache size: %lu\n", packet_cache->size);

  // test cleanup
  void* to_clean_packet_data;
  pportmaster_packet_info to_clean_packet_info;
  // register too many packets
  for (size_t i = 0; i < 10; i++) {
    packet_cache->next_packet_id=3;
    register_packet(packet_cache, packet_info1, packet, packet_len);
    fprintf(stderr, "registered packet. cache size=%d max_size=%d\n", packet_cache->size, packet_cache->max_size);
  }
  // clean packets
  for (size_t i = 0; i < 10; i++) {
    rc = clean_packet_cache(packet_cache, &to_clean_packet_info, &to_clean_packet_data);
    fprintf(stderr, "cleaned packet: %d. cache size=%d max_size=%d\n", rc, packet_cache->size, packet_cache->max_size);
  }
  // add one, clean one
  for (size_t i = 0; i < 2; i++) {
    // add one
    packet_cache->next_packet_id=3;
    register_packet(packet_cache, packet_info3, packet, packet_len);
    fprintf(stderr, "registered packet. cache size=%d max_size=%d\n", packet_cache->size, packet_cache->max_size);
    // clean one
    rc = clean_packet_cache(packet_cache, &to_clean_packet_info, &to_clean_packet_data);
    fprintf(stderr, "cleaned packet: %d. cache size=%d max_size=%d\n", rc, packet_cache->size, packet_cache->max_size);

    // remove one
    rc = retrieve_packet(packet_cache, id3, &packet_info, &packet, &packet_len);
    fprintf(stderr, "retrieved packet: %d. cache size=%d max_size=%d\n", rc, packet_cache->size, packet_cache->max_size);
    // add two
    packet_cache->next_packet_id=3;
    register_packet(packet_cache, packet_info3, packet, packet_len);
    fprintf(stderr, "registered packet. cache size=%d max_size=%d\n", packet_cache->size, packet_cache->max_size);
    packet_cache->next_packet_id=3;
    register_packet(packet_cache, packet_info3, packet, packet_len);
    fprintf(stderr, "registered packet. cache size=%d max_size=%d\n", packet_cache->size, packet_cache->max_size);
    // remove one
    rc = retrieve_packet(packet_cache, id3, &packet_info, &packet, &packet_len);
    fprintf(stderr, "retrieved packet: %d. cache size=%d max_size=%d\n", rc, packet_cache->size, packet_cache->max_size);

    // add one
    register_packet(packet_cache, packet_info3, packet, packet_len);
    fprintf(stderr, "registered packet. cache size=%d max_size=%d\n", packet_cache->size, packet_cache->max_size);
    // remove two
    packet_cache->next_packet_id=3;
    rc = retrieve_packet(packet_cache, id3, &packet_info, &packet, &packet_len);
    fprintf(stderr, "retrieved packet: %d. cache size=%d max_size=%d\n", rc, packet_cache->size, packet_cache->max_size);
    packet_cache->next_packet_id=3;
    rc = retrieve_packet(packet_cache, id3, &packet_info, &packet, &packet_len);
    fprintf(stderr, "retrieved packet: %d. cache size=%d max_size=%d\n", rc, packet_cache->size, packet_cache->max_size);
    // add one
    register_packet(packet_cache, packet_info3, packet, packet_len);
    fprintf(stderr, "registered packet. cache size=%d max_size=%d\n", packet_cache->size, packet_cache->max_size);
  }

  // clean up
  free(packet_info1);
  free(packet_info2);
  free(packet_info3);
  free(packet);

  // success
  fprintf(stderr, "packet_cache tests succeeded\n");
  return 0;
}
