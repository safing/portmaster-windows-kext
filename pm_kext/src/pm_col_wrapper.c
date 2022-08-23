/*
 *  Name:        pm_col_wrapper.c
 *
 *  Owner:       Safing ICS Technologies GmbH
 *
 *  Description: This is a wrapper to include the implementation of collections ("col_*")
 *               in portmaster kernel extension.
 *
 *  Scope:       Kernelmode
 */

#include "pm_kernel.h"
#define LOGGER_NAME "pm_col_wrapper.c"
#include "pm_debug.h"

#define BUILD_ENV_DRIVER
#include "../col/verdict_cache.c"
#include "../col/packet_cache.c"
#include "../col/utils.c"
