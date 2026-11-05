/*
 * ostls_provider.c -- macTLS CFM shared library provider initialization
 *
 * This file provides the CFM fragment initialization and termination
 * routines for the macTLSLib shared library.
 */

#include <stddef.h>
#include "ostls_async.h"

/* Global Open Transport context - owned by the application */
void *g_ostls_ot_context = NULL;

/* CFM Fragment initialization routine */
OSErr OSTLS_LibInit(void)
{
    /* Initialize any library-global state here */
    /* The Open Transport context is owned by the application and
     * must be set via OSTLS_SetOTContext() before use */
    return noErr;
}

/* CFM Fragment termination routine */
void OSTLS_LibTerm(void)
{
    /* Clean up any library-global state here */
    g_ostls_ot_context = NULL;
}

/* Set the Open Transport context (called by application) */
OSErr OSTLS_SetOTContext(void *ot_context)
{
    if (!ot_context) {
        return -1; /* paramErr */
    }
    g_ostls_ot_context = ot_context;
    return noErr;
}

/* Get the Open Transport context */
void *OSTLS_GetOTContext(void)
{
    return g_ostls_ot_context;
}
