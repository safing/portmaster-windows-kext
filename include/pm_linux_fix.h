/*
 *  Name:        pm_linux_fix.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utility-functions
 *
 *  Scope:       Kernelmode
 */

#ifndef __PM_LINUX_FIX_H__
#define __PM_LINUX_FIX_H__

#define __LINUX_ENV__

#include <stdint.h>
#include <stddef.h>
#define INT8    int8_t
#define UINT8   uint8_t
#define INT16   int16_t
#define UINT16  uint16_t
#define INT32   int32_t
#define UINT32  uint32_t
#define ULONG  uint32_t
#define INT64   int64_t
#define UINT64  uint64_t
#define BOOL int
#define VOID  void
#define PVOID  void*
#define SIZE_T size_t
#define HANDLE  int
#define KSPIN_LOCK  int

#endif

#include "pm_common.h"
#include "pm_utils.h"
