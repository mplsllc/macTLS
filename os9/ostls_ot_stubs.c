/*
 * ostls_ot_stubs.c -- Open Transport stubs for missing functions
 *
 * Provides stubs for OT functions not present in the InterfaceLib stub library.
 */

#include <stddef.h>
#include "ostls_async.h"

/* OTSetAsynchronous - set endpoint to asynchronous mode
 * This function is available in Open Transport 1.3+ (Mac OS 8.5+)
 * The InterfaceLib stub may not have it.
 */
OSStatus OTSetAsynchronous(void *ref)
{
    (void)ref;
    return noErr;
}

/* OTSetNonBlocking - set endpoint to non-blocking mode */
OSStatus OTSetNonBlocking(void *ref)
{
    (void)ref;
    return noErr;
}

/* OTUseSyncIdleEvents - enable/disable synchronous idle events */
OSStatus OTUseSyncIdleEvents(void *ref, int enable)
{
    (void)ref;
    (void)enable;
    return noErr;
}

/* YieldToAnyThread - yield to any thread (Thread Manager) */
OSErr YieldToAnyThread(void)
{
    return noErr;
}
