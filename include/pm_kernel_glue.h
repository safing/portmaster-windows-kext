/*
 *  Name:        pm_kernel_glue.h
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains declarations for communication with kernel module
 *               and some Macros to make compile with mingw32 work.
 *
 *  Scope:       Userland
 */

#ifdef __MINGW32__
#define __in
#define __in_opt
#define __out
#define __out_opt
#define __inout
#define __inout_opt
#include <stdint.h>
#define INT8    int8_t
#define UINT8   uint8_t
#define INT16   int16_t
#define UINT16  uint16_t
#define INT32   int32_t
#define UINT32  uint32_t
#define INT64   int64_t
#define UINT64  uint64_t
#endif      /* __MINGW32__ */


extern HANDLE portmaster_kernel_open(const char* portmasterKextPath);
extern BOOLEAN pmStrLen(const wchar_t *s, size_t maxlen, size_t *lengthPtr);
extern BOOLEAN pmStrCpy(wchar_t *dst, size_t dstlen, const wchar_t *src);


