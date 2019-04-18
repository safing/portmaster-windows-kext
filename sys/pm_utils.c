/*
 *  Name:        pm_utils.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: Contains implementation of utility-functions
 *
 *  Scope:       Kernelmode
 */

#include <wdm.h>
#include <windef.h>
#include "pm_common.h"
#include "pm_debug.h"
#include "pm_utils.h"

/*
 * PORTMASTER malloc/free.
 */
static POOL_TYPE non_paged_pool = NonPagedPool;

PVOID portmaster_malloc(SIZE_T size, BOOL paged) {
    void * pv;
    POOL_TYPE pool = (paged? PagedPool: non_paged_pool);
    if (size == 0) {
        return NULL;
    }
    pv= ExAllocatePoolWithTag(pool, size, PORTMASTER_TAG);
    if (pv != 0) {
        RtlZeroMemory(pv, size);
    }
    return pv;
}

VOID portmaster_free(PVOID ptr) {
    if (ptr != NULL) {
        ExFreePoolWithTag(ptr, PORTMASTER_TAG);
    }
}
