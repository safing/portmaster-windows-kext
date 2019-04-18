// stdlib
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define INT8    int8_t
#define UINT8   uint8_t
#define INT16   int16_t
#define UINT16  uint16_t
#define INT32   int32_t
#define UINT32  uint32_t
#define INT64   int64_t
#define UINT64  uint64_t
#define VOID    void
#define BOOL    int
#define TRUE    1
#define FALSE   0
#define ULONG   unsigned long int

// functions to test
#include "../include/pm_checksum.h"

// data for testing
#include "./checksum_data.c"

int testCalcV4(char* name, UINT8* packet, int len, int tsum_loc) {
  int rc = 0;
  UINT16 ipSum = * (UINT16*) &packet[10];
  UINT16 udpSum = * (UINT16*) &packet[tsum_loc];

  fprintf(stderr, "%s IP checksum: 0x%x\n", name, ipSum);
  fprintf(stderr, "%s TR checksum: 0x%x\n", name, udpSum);
  packet[10] = packet[11] = packet[tsum_loc] = packet[tsum_loc+1] = 1;

  calc_ipv4_checksum((void*) packet, len, TRUE);

  if (ipSum != * (UINT16*) &packet[10]) {
    fprintf(stderr, "%s IP checksum mismatch, got: 0x%x\n", name, * (UINT16*) &packet[10]);
    rc += 1;
  }
  if (udpSum != * (UINT16*) &packet[tsum_loc]) {
    fprintf(stderr, "%s TR checksum mismatch, got: 0x%x\n", name, * (UINT16*) &packet[tsum_loc]);
    rc += 1;
  }

  return rc;
}

int testCalcV6(char* name, UINT8* packet, int len, int tsum_loc) {
  int rc = 0;
  UINT16 udpSum = * (UINT16*) &packet[tsum_loc];

  fprintf(stderr, "%s TR checksum: 0x%x\n", name, udpSum);
  packet[tsum_loc] = packet[tsum_loc+1] = 1;

  calc_ipv6_checksum((void*) packet, len, TRUE);

  if (udpSum != * (UINT16*) &packet[tsum_loc]) {
    fprintf(stderr, "%s TR checksum mismatch, got: 0x%x\n", name, * (UINT16*) &packet[tsum_loc]);
    rc += 1;
  }

  return rc;
}

int main() {
  int rc = 0;

  rc += testCalcV4("v4dnsQuery", v4dnsQuery, 71, 26);
  rc += testCalcV4("v4tlsData", v4tlsData, 89, 36);
  rc += testCalcV6("v6dnsQuery", v6dnsQuery, 91, 46);
  rc += testCalcV6("v6tlsData", v6tlsData, 91, 56);
  rc += testCalcV6("v6forgedDNSQuery", v6forgedDNSQuery, 107, 46+16);

  if (rc == 0) {
    // success
    fprintf(stderr, "checksum tests succeeded\n");
  }
  return rc;
}
