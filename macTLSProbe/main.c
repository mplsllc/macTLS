/*
 * macTLSProbe -- macTLSLib consumer application for Mac OS 9.
 *
 * Demonstrates loading and using the macTLSLib CFM shared library to
 * perform a certificate-validated HTTPS request over Open Transport.
 *
 * Flow:
 *   1. InitOpenTransportInContext -> g_ostls_ot_context
 *   2. OSTLS_SetOTContext(g_ostls_ot_context)
 *   3. OSTLS_LibInit()
 *   4. OSTLS_New() + OSTLS_Start()
 *   5. Pump loop: OSTLS_Pump() -> OSTLS_Write() (GET request) ->
 *      OSTLS_Read() until peer closes
 *   6. OSTLS_Close() + OSTLS_Dispose()
 *   7. OSTLS_LibTerm()
 *   8. CloseOpenTransportInContext()
 *
 * Built with macMAKE v0.1.1 (classic-ppc-xcoff-c-v1, CodeWarrior MSL compatible).
 */

/* FSSpec is needed by OpenTransportProviders.h (via OpenTptInternet.h)
 * but comes from Files.h. Define a minimal version here to avoid
 * pulling in Files.h (which can drag in stdarg.h via Universal Interfaces). */
struct FSSpec {
    short vRefNum;
    long parID;
    unsigned char name[64];
};
typedef struct FSSpec FSSpec;

#ifndef NULL
#define NULL 0
#endif

#include <OpenTransport.h>
#include <OpenTptInternet.h>

#include "../os9/ostls_async.h"

/* Open Transport context, owned by this application */
static OTClientContextPtr g_ostls_ot_context = NULL;

/* --- Open Transport stubs (OpenTransportLib not linked on Linux build) --- */
OSStatus
InitOpenTransportInContext(unsigned long mask, OTClientContextPtr *context)
{
    (void)mask;
    *context = NULL;
    return noErr;
}

void
CloseOpenTransportInContext(OTClientContextPtr context)
{
    (void)context;
}

/* --- Tiny C library replacements (no MSL headers in freestanding) --- */
static void
memset_void(void *dst, int c, unsigned long n)
{
    unsigned char *p = (unsigned char *)dst;
    while (n-- > 0) *p++ = (unsigned char)c;
}

static unsigned long
strlen_c(const char *s)
{
    unsigned long n = 0;
    while (*s) { n++; s++; }
    return n;
}

/* Simple tick counter replacement for TickCount() (avoids Events.h/stdarg.h) */
static unsigned long
tick_count(void)
{
    /* On real Mac OS this would call TickCount(). Here we use a
     * software counter incremented each pump iteration as a rough
     * timeout mechanism. */
    static unsigned long ticks = 0;
    return ticks++;
}

/* ------------------------------------------------------------------ */
/* Open Transport lifecycle                                           */
/* ------------------------------------------------------------------ */
static OSStatus
ot_init(void)
{
    return InitOpenTransportInContext(kInitOTForApplicationMask,
                                      &g_ostls_ot_context);
}

static void
ot_close(void)
{
    if (g_ostls_ot_context != NULL) {
        CloseOpenTransportInContext(g_ostls_ot_context);
        g_ostls_ot_context = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Main: perform one HTTPS GET                                        */
/* ------------------------------------------------------------------ */
int
main(void)
{
    OSTLSConfig     cfg;
    OSTLSConnection *conn = NULL;
    OSTLSEvent      ev;
    OSErr           err;
    char            req[256];
    char            buf[1024];
    UInt32          nread, written, total;
    UInt32          deadline, read_until;
    int             state_open = 0;
    int             sent = 0;
    int             recv_bytes = 0;

    OSTLS_LogLine("macTLSProbe: starting");

    /* --- Open Transport --- */
    OSTLS_LogLine("macTLSProbe: InitOpenTransportInContext...");
    if (ot_init() != noErr) {
        OSTLS_LogLine("macTLSProbe: FATAL: Open Transport init failed");
        return 1;
    }
    OSTLS_LogLine("macTLSProbe: Open Transport initialized");

    /* --- macTLSLib wiring --- */
    OSTLS_LogLine("macTLSProbe: OSTLS_SetOTContext...");
    if (OSTLS_SetOTContext(g_ostls_ot_context) != noErr) {
        OSTLS_LogLine("macTLSProbe: FATAL: OSTLS_SetOTContext failed");
        ot_close();
        return 1;
    }

    OSTLS_LogLine("macTLSProbe: OSTLS_LibInit...");
    if (OSTLS_LibInit() != noErr) {
        OSTLS_LogLine("macTLSProbe: FATAL: OSTLS_LibInit failed");
        ot_close();
        return 1;
    }
    OSTLS_LogLine("macTLSProbe: macTLSLib initialized");

    /* --- Configure connection --- */
    memset_void(&cfg, 0, sizeof(cfg));
    cfg.host                 = "google.com";
    cfg.port                 = 443;
    cfg.server_name          = "google.com";
    cfg.connect_timeout_ticks = 6000;
    cfg.handshake_timeout_ticks = 6000;
    cfg.user_refcon          = NULL;

    /* --- Build HTTP GET request (manual, no sprintf) --- */
    {
        char *p = req;
        const char *s = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";
        while (*s) *p++ = *s++;
        *p = '\0';
    }

    /* --- Create and start connection --- */
    OSTLS_LogLine("macTLSProbe: OSTLS_New...");
    if (OSTLS_New(&conn, &cfg) != kOSTLSAsync_OK || conn == NULL) {
        OSTLS_LogLine("macTLSProbe: FATAL: OSTLS_New failed");
        OSTLS_LibTerm();
        ot_close();
        return 1;
    }

    OSTLS_LogLine("macTLSProbe: OSTLS_Start...");
    if (OSTLS_Start(conn) != kOSTLSAsync_OK) {
        OSTLS_LogLine("macTLSProbe: FATAL: OSTLS_Start failed");
        OSTLS_Dispose(conn);
        OSTLS_LibTerm();
        ot_close();
        return 1;
    }

    total = 0;
    deadline = tick_count() + 6000;   /* ~6000 pump iterations */

    OSTLS_LogLine("macTLSProbe: entering pump loop...");

    for (;;) {
        /* Overall deadline */
        if (tick_count() > deadline) {
            OSTLS_LogLine("macTLSProbe: overall timeout");
            break;
        }

        err = OSTLS_Pump(conn, 8, &ev);

        if (err != kOSTLSAsync_OK) {
            OSTLS_LogLine("macTLSProbe: pump returned error");
            break;
        }

        switch (OSTLS_GetState(conn)) {
        case kOSTLSStateOpen:
            if (!state_open) {
                state_open = 1;
                read_until = tick_count() + 1000; /* ~1000 pump iterations */
                OSTLS_LogLine("macTLSProbe: connection open");
            }
            break;

        case kOSTLSStateFailed:
            OSTLS_LogLine("macTLSProbe: connection failed");
            goto done;

        case kOSTLSStateClosed:
            OSTLS_LogLine("macTLSProbe: peer closed");
            goto done;

        default:
            break;
        }

        /* Send GET request once the connection is open */
        if (state_open && !sent) {
            unsigned long req_len = 0;
            const char *s = req;
            while (*s) { req_len++; s++; }
            written = 0;
            if (OSTLS_Write(conn, req, req_len, &written)
                    == kOSTLSAsync_OK && written == req_len) {
                sent = 1;
                OSTLS_LogLine("macTLSProbe: GET request sent");
            }
        }

        /* Read response data */
        if (state_open) {
            for (;;) {
                nread = 0;
                if (OSTLS_Read(conn, buf, (UInt32)sizeof(buf), &nread)
                        != kOSTLSAsync_OK || nread == 0)
                    break;
                total += (int)nread;
            }
        }

        /* Stop draining after read_until */
        if (state_open && tick_count() > read_until) {
            OSTLS_LogLine("macTLSProbe: read drain complete");
            break;
        }
    }

done:
    OSTLS_LogLine("macTLSProbe: cleaning up");
    OSTLS_Close(conn);
    OSTLS_Dispose(conn);
    OSTLS_LibTerm();
    ot_close();

    OSTLS_LogLine("macTLSProbe: done");
    return 0;
}
