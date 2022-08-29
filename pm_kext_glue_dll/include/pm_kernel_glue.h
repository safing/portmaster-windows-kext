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

extern HANDLE portmasterKernelOpen(const char* portmasterKextPath);
extern bool pmStrLen(const wchar_t *s, size_t maxlen, size_t *lengthPtr);
extern bool pmStrCpy(wchar_t *dst, size_t dstlen, const wchar_t *src);


