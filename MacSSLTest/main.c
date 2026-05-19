/*
 * MacSSLTest -- standalone Carbon app for Stage A validation.
 *
 * What it does (and ONLY does):
 *   1. Toolbox / Appearance init (Carbon-style, skip the deprecated
 *      InitGraf/InitFonts/etc. inits per CarbonLib convention).
 *   2. Call OSTLS_SmokeTest() once.
 *   3. Open a small window and DrawString the result code.
 *   4. Wait for a mouse click or key press, then quit.
 *
 * What it deliberately does NOT do:
 *   - No Open Transport (smoke test is non-network by design).
 *   - No QuickTime, no Appearance themes beyond default, no menus.
 *   - No file I/O, no preferences, no settings, no resources beyond
 *     the 'carb' Carbon-fragment marker in MacSSLTest.rsrc.
 *
 * Once the smoke test passes on real OS 9 hardware (and the Stage A.5
 * mul64 probe passes too), this file evolves into the seed of
 * MacSSL Proxy: replace the "show dialog + quit" tail with a TCP
 * listener + HTTP proxy parser + BearSSL upstream fetch.
 */

#include "macssltest_prefix.h"

/*
 * Avoid the <Carbon.h> umbrella. Carbon.h chains through CoreServices.h
 * which pulls in Threads.h. On CW8 installations where the Java SDK
 * support folder is on the system search path, a HotSpot JVM Threads.h
 * can be found before Apple's, producing a cascade of JVM-internal
 * errors (oobj.h, typedefs.h, winnt.h, winbase.h ...). Including the
 * specific Toolbox headers we actually need avoids that chain entirely
 * and is also faster to compile.
 */
#include <Quickdraw.h>
#include <Windows.h>
#include <Events.h>
#include <Fonts.h>
#include <Gestalt.h>
#include <Sound.h>
#ifdef __MWERKS__
#include <Appearance.h>     /* CarbonLib only; absent from Retro68 pre-flight */
#include <Files.h>          /* Open Transport pulls in Files types */
#include <OpenTransport.h>  /* InitOpenTransportInContext / OTClientContextPtr */
#include <OpenTptInternet.h>/* TCP configuration constants */
#endif

#include <stdio.h>
#include <string.h>

#include "ostls_smoketest.h"
#include "ostls_mul64_probe.h"
#include "ostls_b1_tcp.h"
#include "ostls_b2_handshake.h"
#include "ostls_b3_handshake.h"
#include "ostls_b4_https_get.h"
#include "ostls_c1_listener.h"
#include "ostls_log.h"


/*
 * Stage B targets.
 *   B1 (TCP only):           example.com:443 -- public TCP sanity check
 *   B2 (insecure handshake): example.com:443 -- isolates the record I/O
 *                            loop from any validation question
 *   B3 (validated handshake): google.com:443 -- chains through GTS Root R1
 *                             (or GTS Root R4 for the ECDSA path), both
 *                             embedded in ostls_b3_anchors. Picked over
 *                             example.com so we're validating macSSL's
 *                             X.509 path, not chasing IANA cert rotation.
 */
#define OSTLS_B1_TARGET     "example.com:443"
#define OSTLS_B2_TARGET     "example.com:443"
#define OSTLS_B2_SERVERNAME "example.com"
#define OSTLS_B3_TARGET     "google.com:443"
#define OSTLS_B3_SERVERNAME "google.com"
#define OSTLS_B4_TARGET     "google.com:443"
#define OSTLS_B4_SERVERNAME "google.com"
#define OSTLS_B4_REQPATH    "/"

/*
 * Stage C1 listens on this port for one incoming TCP connection.
 * 8765 matches the convention MacSurf already uses for its HTTP proxy
 * so once Stage C ships the operator can point any classic browser
 * at the same port without retraining.
 */
#define OSTLS_C1_PORT       8765


/*
 * Open Transport client context, populated by InitOpenTransportInContext
 * at startup and torn down at shutdown. The B1 probe and any later
 * Stage B code that opens endpoints reference this via
 *   extern OTClientContextPtr g_ostls_ot_context;
 * in their own source files.
 *
 * CW8's OT headers don't always define kInitOTForApplicationMask; per
 * the MacSurf workaround we pin it to the documented bit value when
 * the macro is missing.
 */
#ifdef __MWERKS__
OTClientContextPtr g_ostls_ot_context = NULL;
#ifndef kInitOTForApplicationMask
#define kInitOTForApplicationMask 0x00000002L
#endif
#else
void *g_ostls_ot_context = NULL;
#endif


/* ------------------------------------------------------------------- */
/* Helpers                                                             */
/* ------------------------------------------------------------------- */

/*
 * Convert a C string to a Pascal string in-place into the supplied
 * buffer. Truncates at 254 chars. CW8 has c2pstr() but it mutates the
 * source buffer; this version is non-destructive and safer.
 */
static void
c_to_pstr(const char *src, Str255 dst)
{
    size_t n = strlen(src);
    if (n > 254) {
        n = 254;
    }
    dst[0] = (unsigned char)n;
    memcpy(&dst[1], src, n);
}


/*
 * Decode an OSTLS smoke-test or Mul64-probe result code into a
 * human-readable label. Codes correspond to kOSTLSSmoke* in
 * os9/ostls_smoketest.h and kOSTLSMul64* in os9/ostls_mul64_probe.h.
 */
static const char *
smoke_label(OSErr code)
{
    switch ((short)code) {
    case noErr:                            return "OK";
    case kOSTLSSmokeBadEngineAfterReset:   return "engine error after reset";
    case kOSTLSSmokeNoSendrecAfterReset:   return "engine not asking to send";
    case kOSTLSSmokeClientResetReturned0:  return "br_ssl_client_reset = 0";
    case kOSTLSSmokeEntropyInjectFailed:   return "entropy inject failed";
    case kOSTLSMul64FailA_Raw:             return "mul64 A raw -- 0x12345678 * 0x9ABCDEF0";
    case kOSTLSMul64FailA_CT:              return "mul64 A CT  -- |0x80000000 pattern A";
    case kOSTLSMul64FailB_Raw:             return "mul64 B raw -- 0x7FFFFFFF^2";
    case kOSTLSMul64FailB_CT:              return "mul64 B CT  -- |0x80000000 pattern B";
    case kOSTLSMul64FailC_Raw:             return "mul64 C raw -- 0x00010001^2";
    case kOSTLSMul64FailC_CT:              return "mul64 C CT  -- |0x80000000 pattern C";
    case kOSTLSMul64FailD_Raw:             return "mul64 D raw -- 0xDEADBEEF * 0xCAFEBABE";
    case kOSTLSMul64FailD_CT:              return "mul64 D CT  -- |0x80000000 pattern D";
    case kOSTLSB1_BadArgs:                 return "B1 bad args";
    case kOSTLSB1_OTConfigFail:            return "B1 OTCreateConfiguration failed";
    case kOSTLSB1_OTOpenEndptFail:         return "B1 OTOpenEndpointInContext failed";
    case kOSTLSB1_OTBindFail:              return "B1 OTBind failed";
    case kOSTLSB1_OTDnsAddrFail:           return "B1 OTInitDNSAddress failed";
    case kOSTLSB1_OTConnectFail:           return "B1 OTConnect failed";
    case kOSTLSB2_BadArgs:                 return "B2 bad args";
    case kOSTLSB2_OTConfigFail:            return "B2 OTCreateConfiguration failed";
    case kOSTLSB2_OTOpenEndptFail:         return "B2 OTOpenEndpoint failed";
    case kOSTLSB2_OTBindFail:              return "B2 OTBind failed";
    case kOSTLSB2_OTDnsAddrFail:           return "B2 OTInitDNSAddress failed";
    case kOSTLSB2_OTConnectFail:           return "B2 OTConnect failed";
    case kOSTLSB2_EntropyFail:             return "B2 entropy inject failed";
    case kOSTLSB2_ClientResetFail:         return "B2 br_ssl_client_reset failed";
    case kOSTLSB2_OTSndFail:               return "B2 OTSnd failed mid-handshake";
    case kOSTLSB2_OTRcvFail:               return "B2 OTRcv failed mid-handshake";
    case kOSTLSB2_PeerClosedEarly:         return "B2 peer closed before handshake";
    case kOSTLSB2_HandshakeTimeout:        return "B2 handshake timed out (60s)";
    case kOSTLSB2_BearSSLError:            return "B2 BearSSL engine error";
    case kOSTLSB3_BadArgs:                 return "B3 bad args";
    case kOSTLSB3_ClockBefore2000:         return "B3 system clock before 2000";
    case kOSTLSB3_OTConfigFail:            return "B3 OTCreateConfiguration failed";
    case kOSTLSB3_OTOpenEndptFail:         return "B3 OTOpenEndpoint failed";
    case kOSTLSB3_OTBindFail:              return "B3 OTBind failed";
    case kOSTLSB3_OTDnsAddrFail:           return "B3 OTInitDNSAddress failed";
    case kOSTLSB3_OTConnectFail:           return "B3 OTConnect failed";
    case kOSTLSB3_EntropyFail:             return "B3 entropy inject failed";
    case kOSTLSB3_ClientResetFail:         return "B3 br_ssl_client_reset failed";
    case kOSTLSB3_OTSndFail:               return "B3 OTSnd failed mid-handshake";
    case kOSTLSB3_OTRcvFail:               return "B3 OTRcv failed mid-handshake";
    case kOSTLSB3_PeerClosedEarly:         return "B3 peer closed before handshake";
    case kOSTLSB3_HandshakeTimeout:        return "B3 handshake timed out";
    case kOSTLSB3_X509NotTrusted:          return "B3 X509 unknown CA / chain not trusted";
    case kOSTLSB3_X509Expired:             return "B3 X509 cert expired / not yet valid";
    case kOSTLSB3_X509HostnameMismatch:    return "B3 X509 hostname mismatch";
    case kOSTLSB3_X509BadSignature:        return "B3 X509 bad signature";
    case kOSTLSB3_X509TimeUnknown:         return "B3 X509 time unknown (clock?)";
    case kOSTLSB3_X509Other:               return "B3 X509 other validation error";
    case kOSTLSB3_BearSSLError:            return "B3 BearSSL engine error";
    case kOSTLSB4_BadArgs:                 return "B4 bad args";
    case kOSTLSB4_ClockBefore2000:         return "B4 system clock before 2000";
    case kOSTLSB4_OTConfigFail:            return "B4 OTCreateConfiguration failed";
    case kOSTLSB4_OTOpenEndptFail:         return "B4 OTOpenEndpoint failed";
    case kOSTLSB4_OTBindFail:              return "B4 OTBind failed";
    case kOSTLSB4_OTDnsAddrFail:           return "B4 OTInitDNSAddress failed";
    case kOSTLSB4_OTConnectFail:           return "B4 OTConnect failed";
    case kOSTLSB4_EntropyFail:             return "B4 entropy inject failed";
    case kOSTLSB4_ClientResetFail:         return "B4 br_ssl_client_reset failed";
    case kOSTLSB4_OTSndFail:               return "B4 OTSnd failed";
    case kOSTLSB4_OTRcvFail:               return "B4 OTRcv failed";
    case kOSTLSB4_HandshakeTimeout:        return "B4 handshake/IO timed out";
    case kOSTLSB4_BearSSLError:            return "B4 BearSSL engine error";
    case kOSTLSB4_RequestTooBig:           return "B4 request too big for sendapp buf";
    case kOSTLSB4_NoBytesReceived:         return "B4 peer closed before any plaintext";
    case kOSTLSC1_BadArgs:                 return "C1 bad args";
    case kOSTLSC1_OTConfigFail:            return "C1 OTCreateConfiguration failed";
    case kOSTLSC1_OTOpenEndptFail:         return "C1 OTOpenEndpoint failed (listener)";
    case kOSTLSC1_OTBindFail:              return "C1 OTBind failed (port in use?)";
    case kOSTLSC1_OTListenFail:            return "C1 OTListen failed";
    case kOSTLSC1_OTAcceptOpenFail:        return "C1 OTOpenEndpoint failed (child)";
    case kOSTLSC1_OTAcceptBindFail:        return "C1 OTBind failed (child)";
    case kOSTLSC1_OTAcceptFail:            return "C1 OTAccept failed";
    case kOSTLSC1_OTRcvFail:               return "C1 OTRcv failed";
    case kOSTLSC1_PeerClosedEmpty:         return "C1 peer connected but sent nothing";
    }
    return "unknown failure";
}


/* ------------------------------------------------------------------- */
/* Toolbox init (Carbon discipline)                                    */
/* ------------------------------------------------------------------- */

/*
 * Mirror MacSurf's pattern: skip InitGraf/InitFonts/InitWindows/
 * InitMenus/TEInit/InitDialogs under Carbon, but keep InitCursor() and
 * FlushEvents(). Register the Appearance Manager only if Gestalt
 * confirms it is present.
 */
static void
toolbox_init(void)
{
    InitCursor();
    FlushEvents(everyEvent, 0);

#ifdef __MWERKS__
    /* Gestalt-gated Appearance init. Skipped under Retro68 pre-flight
     * (multiversal headers don't ship Appearance.h); CW8's Carbon.h
     * pulls in everything we need. */
    {
        long response;
        if (Gestalt(gestaltAppearanceAttr, &response) == noErr) {
            RegisterAppearanceClient();
        }
    }
#endif
}


/* ------------------------------------------------------------------- */
/* Result display                                                      */
/* ------------------------------------------------------------------- */

/*
 * Open a single modeless window, draw the result, and pump events
 * until the user clicks or types. No menu bar, no fancy chrome.
 *
 * Caller supplies the three text lines and the title. main() owns the
 * stage-result logic; this function just renders.
 */
static void
show_result_and_wait(const char *title_c,
                     const char *line1_c,
                     const char *line2_c)
{
    WindowRef win;
    Rect bounds;
    EventRecord ev;
    Boolean done = false;
    Str255 title;
    Str255 line1;
    Str255 line2;
    Str255 line3;

    c_to_pstr(title_c, title);
    c_to_pstr(line1_c, line1);
    c_to_pstr(line2_c, line2);
    c_to_pstr("Click mouse or press any key to quit.", line3);

    /* Open the window. */
    SetRect(&bounds, 60, 60, 540, 220);
    win = NewCWindow(NULL, &bounds, title, true,
        noGrowDocProc, (WindowRef)-1L, true, 0L);
    if (win == NULL) {
        SysBeep(30);
        return;
    }
    SetPortWindowPort(win);

    /* Pump events until quit. Drawing happens on every updateEvt so
     * the window stays correct if it's covered and uncovered. */
    while (!done) {
        WaitNextEvent(everyEvent, &ev, 30, NULL);
        switch (ev.what) {
        case mouseDown:
        case keyDown:
            done = true;
            break;
        case updateEvt:
            BeginUpdate((WindowRef)ev.message);
            if ((WindowRef)ev.message == win) {
                Rect r;
                GetWindowPortBounds(win, &r);
                EraseRect(&r);

                TextFont(kFontIDGeneva);
                TextSize(12);
                TextFace(bold);
                MoveTo(20, 40);
                DrawString(line1);

                TextFace(0);
                MoveTo(20, 70);
                DrawString(line2);

                TextSize(10);
                MoveTo(20, 130);
                DrawString(line3);
            }
            EndUpdate((WindowRef)ev.message);
            break;
        }
    }

    DisposeWindow(win);
}


/* ------------------------------------------------------------------- */
/* Entry point                                                         */
/* ------------------------------------------------------------------- */

/*
 * Open Transport lifecycle. Initialised once at startup, closed once at
 * shutdown. The B1 probe (and any subsequent Stage B work) opens its
 * own endpoints against this context. Failure is non-fatal -- we still
 * run the in-memory probes (A.5, A) so the user sees a useful result
 * window even on a machine where OT is missing or broken.
 */
static OSStatus
ostls_ot_init(void)
{
#ifdef __MWERKS__
    return InitOpenTransportInContext(kInitOTForApplicationMask,
                                      &g_ostls_ot_context);
#else
    return 0;
#endif
}

static void
ostls_ot_close(void)
{
#ifdef __MWERKS__
    if (g_ostls_ot_context != NULL) {
        CloseOpenTransportInContext(g_ostls_ot_context);
        g_ostls_ot_context = NULL;
    }
#endif
}


int
main(void)
{
    OSErr     a5_result;
    OSErr     a_result;
    OSErr     b1_result;
    OSStatus  ot_init_status;
    char      b1_msg[160];
    char      line1_buf[200];
    char      line2_buf[200];
    char      title_buf[80];

    toolbox_init();

    /*
     * Bring up the file-backed logger first so every probe result
     * is captured on disk in MacSSLTest.log on the Desktop. The log
     * is the durable record we read back over scp; the result window
     * is just the live UI.
     */
    (void)OSTLS_LogInit();
    OSTLS_LogLine("==== MacSSLTest run ====");

    b1_msg[0] = '\0';

    /*
     * Stage A.5: 32x32->64 multiply codegen probe. If the underlying
     * arithmetic is wrong on this hardware, every Stage A or Stage B
     * pass below would be meaningless. Probe the kernel first.
     */
    OSTLS_LogLine("Stage A.5  mul64 probe              ...");
    a5_result = OSTLS_Mul64Probe();
    OSTLS_LogLinef("Stage A.5  mul64 probe              -> code=%d %s",
                   (int)a5_result,
                   (a5_result == noErr) ? "OK" : smoke_label(a5_result));
    if (a5_result != noErr) {
        sprintf(title_buf, "MacSSLTest -- mul64 probe FAILED");
        sprintf(line1_buf, "Stage A.5 mul64 FAILED (code %d)",
                (int)a5_result);
        sprintf(line2_buf, "Gate: %s", smoke_label(a5_result));
        show_result_and_wait(title_buf, line1_buf, line2_buf);
        OSTLS_LogClose();
        return 0;
    }

    /*
     * Stage A: BearSSL build / init / state machine reaches SENDREC.
     * Pure in-memory; does not touch OT. If this fails the link is
     * fine but BearSSL itself can't get out of the starting blocks.
     */
    OSTLS_LogLine("Stage A    BearSSL smoke            ...");
    a_result = OSTLS_SmokeTest();
    OSTLS_LogLinef("Stage A    BearSSL smoke            -> code=%d %s",
                   (int)a_result,
                   (a_result == noErr) ? "OK (engine reports SENDREC)"
                                       : smoke_label(a_result));
    if (a_result != noErr) {
        sprintf(title_buf, "MacSSLTest -- Stage A smoke FAILED");
        sprintf(line1_buf, "Stage A smoke FAILED (code %d)",
                (int)a_result);
        sprintf(line2_buf, "Gate: %s", smoke_label(a_result));
        show_result_and_wait(title_buf, line1_buf, line2_buf);
        OSTLS_LogClose();
        return 0;
    }

    /*
     * Stage B1: raw Open Transport TCP connect probe. First time this
     * binary touches the network. OT must be initialised before the
     * probe runs; we report initialisation failure distinctly so a
     * "no OT on this machine" result doesn't get conflated with "OT
     * fine, but this host is unreachable".
     */
    OSTLS_LogLine("OT init    InitOpenTransportInContext...");
    ot_init_status = ostls_ot_init();
    OSTLS_LogLinef("OT init    InitOpenTransportInContext-> ot_err=%ld%s",
                   (long)ot_init_status,
                   (ot_init_status == noErr) ? " OK" : " FAIL");
    if (ot_init_status != noErr) {
        sprintf(title_buf, "MacSSLTest -- OT init FAILED");
        sprintf(line1_buf,
                "InitOpenTransportInContext FAILED (ot_err=%ld)",
                (long)ot_init_status);
        sprintf(line2_buf,
                "Stage A + A.5 OK; OT unavailable so B1 was skipped.");
        show_result_and_wait(title_buf, line1_buf, line2_buf);
        OSTLS_LogClose();
        return 0;
    }

    OSTLS_LogLinef("Stage B1   OT TCP connect target=%s ...",
                   OSTLS_B1_TARGET);
    b1_result = OSTLS_B1_TCP_Probe(OSTLS_B1_TARGET, b1_msg, sizeof b1_msg);
    OSTLS_LogLinef("Stage B1   OT TCP connect           -> code=%d %s",
                   (int)b1_result, b1_msg);

    if (b1_result != kOSTLSB1_OK) {
        sprintf(title_buf, "MacSSLTest -- Stage B1 FAILED");
        sprintf(line1_buf, "Stage B1 FAILED (code %d): %.140s",
                (int)b1_result, b1_msg);
        sprintf(line2_buf,
                "Gate: %s (target=%s)",
                smoke_label(b1_result), OSTLS_B1_TARGET);
        show_result_and_wait(title_buf, line1_buf, line2_buf);
        ostls_ot_close();
        OSTLS_LogClose();
        return 0;
    }

    /*
     * Stage B2: BearSSL handshake (insecure validator) over OT against
     * the same target. First time TLS bytes actually flow on this
     * platform. Uses gB2-static contexts so the partition footprint is
     * predictable up front.
     */
    {
        OSErr b2_result;
        char  b2_msg[180];

        OSTLS_LogLinef("Stage B2   TLS handshake (insecure) target=%s ...",
                       OSTLS_B2_TARGET);
        b2_result = OSTLS_B2_Handshake_Probe(
            OSTLS_B2_TARGET, OSTLS_B2_SERVERNAME,
            b2_msg, sizeof b2_msg);
        OSTLS_LogLinef("Stage B2   TLS handshake (insecure) -> code=%d %s",
                       (int)b2_result, b2_msg);

        if (b2_result != kOSTLSB2_OK) {
            sprintf(title_buf, "MacSSLTest -- Stage B2 FAILED");
            sprintf(line1_buf, "Stage B2 FAILED (code %d): %.140s",
                (int)b2_result, b2_msg);
            sprintf(line2_buf,
                "Gate: %s (target=%s)",
                smoke_label(b2_result), OSTLS_B2_TARGET);
            show_result_and_wait(title_buf, line1_buf, line2_buf);
            ostls_ot_close();
            OSTLS_LogClose();
            return 0;
        }
    }

    /*
     * Stage B3: validated TLS handshake against google.com:443. Real
     * br_x509_minimal with embedded trust anchors and the Mac system
     * clock fed in. Failures here distinguish CA / expiry / hostname
     * / clock / signature errors via dedicated result codes so the
     * window points at exactly which validation gate broke.
     */
    {
        OSErr b3_result;
        char  b3_msg[180];

        OSTLS_LogLinef("Stage B3   TLS handshake (validated) target=%s ...",
                       OSTLS_B3_TARGET);
        b3_result = OSTLS_B3_Validated_Probe(
            OSTLS_B3_TARGET, OSTLS_B3_SERVERNAME,
            b3_msg, sizeof b3_msg);
        OSTLS_LogLinef("Stage B3   TLS handshake (validated) -> code=%d %s",
                       (int)b3_result, b3_msg);

        if (b3_result != kOSTLSB3_OK) {
            sprintf(title_buf, "MacSSLTest -- Stage B3 FAILED");
            sprintf(line1_buf, "Stage B3 FAILED (code %d): %.140s",
                (int)b3_result, b3_msg);
            sprintf(line2_buf,
                "Gate: %s (target=%s)",
                smoke_label(b3_result), OSTLS_B3_TARGET);
            OSTLS_LogBlank();
            OSTLS_LogLinef("==== Stage B3 FAILED (code=%d) ====",
                           (int)b3_result);
            show_result_and_wait(title_buf, line1_buf, line2_buf);
            ostls_ot_close();
            OSTLS_LogClose();
            return 0;
        }
    }

    /*
     * Stage B4: tiny HTTPS GET. Opens a fresh validated session
     * against google.com:443, sends "GET / HTTP/1.0" with
     * Connection: close, captures the first 96 bytes of the
     * decrypted response. The captured prefix is logged with
     * escaping for control chars so it survives unbroken to the log
     * file even when the response contains CR/LF.
     */
    {
        OSErr b4_result;
        char  b4_msg[180];
        char  b4_prefix[96];

        OSTLS_LogLinef("Stage B4   HTTPS GET %s%s ...",
                       OSTLS_B4_TARGET, OSTLS_B4_REQPATH);
        b4_result = OSTLS_B4_HTTPS_Get_Probe(
            OSTLS_B4_TARGET, OSTLS_B4_SERVERNAME, OSTLS_B4_REQPATH,
            b4_prefix, sizeof b4_prefix,
            b4_msg, sizeof b4_msg);
        OSTLS_LogLinef("Stage B4   HTTPS GET                -> code=%d %s",
                       (int)b4_result, b4_msg);

        if (b4_result != kOSTLSB4_OK) {
            sprintf(title_buf, "MacSSLTest -- Stage B4 FAILED");
            sprintf(line1_buf, "Stage B4 FAILED (code %d): %.140s",
                (int)b4_result, b4_msg);
            sprintf(line2_buf,
                "Gate: %s (target=%s)",
                smoke_label(b4_result), OSTLS_B4_TARGET);
            OSTLS_LogBlank();
            OSTLS_LogLinef("==== Stage B4 FAILED (code=%d) ====",
                           (int)b4_result);
            show_result_and_wait(title_buf, line1_buf, line2_buf);
            ostls_ot_close();
            OSTLS_LogClose();
            return 0;
        }
    }

    /*
     * Stage C1: open a TCP listener on OSTLS_C1_PORT and accept a
     * single inbound connection. The UI freezes during OTListen
     * because we're in synchronous + blocking mode -- this is
     * acceptable for the gate. The log line below is written + flushed
     * BEFORE the freeze, so an operator pulling MacSSLTest.log can
     * confirm the listener is up and waiting.
     *
     * To trigger the accept on the same Mac:
     *   telnet localhost 8765
     *   <type "GET /test HTTP/1.0" + RETURN twice + ctrl-]> quit
     *
     * From another machine on the LAN:
     *   nc <mac-ip> 8765
     *   <type anything> ctrl-D
     */
    {
        OSErr c1_result;
        char  c1_msg[180];
        char  c1_request[256];

        OSTLS_LogLinef("Stage C1   listening on port %u ...",
                       (unsigned)OSTLS_C1_PORT);
        OSTLS_LogLine("           (UI is frozen until a client connects)");

        c1_result = OSTLS_C1_Listener_Probe(
            (unsigned short)OSTLS_C1_PORT,
            c1_request, sizeof c1_request,
            c1_msg, sizeof c1_msg);

        OSTLS_LogLinef("Stage C1   listener result          -> code=%d %s",
                       (int)c1_result, c1_msg);

        if (c1_result == kOSTLSC1_OK) {
            char short_req[80];
            size_t i;
            size_t n = strlen(c1_request);
            if (n > sizeof short_req - 4) {
                n = sizeof short_req - 4;
            }
            for (i = 0; i < n; i++) {
                unsigned char c = (unsigned char)c1_request[i];
                if (c == '\r' || c == '\n' || c < 0x20 || c >= 0x7F) {
                    short_req[i] = ' ';
                } else {
                    short_req[i] = (char)c;
                }
            }
            short_req[n] = '\0';

            /* Log the full request body with escape-rendered control
             * chars so it survives unbroken to the file log. */
            {
                char dbg[320];
                size_t pos;
                size_t j;
                pos = (size_t)sprintf(dbg, "Stage C1   request bytes [%lu]: ",
                                      (unsigned long)n);
                for (j = 0; j < n && pos < sizeof dbg - 4; j++) {
                    unsigned char c = (unsigned char)c1_request[j];
                    if (c == 0x0D) {
                        dbg[pos++] = '\\';
                        dbg[pos++] = 'r';
                    } else if (c == 0x0A) {
                        dbg[pos++] = '\\';
                        dbg[pos++] = 'n';
                    } else if (c >= 0x20 && c < 0x7F) {
                        dbg[pos++] = (char)c;
                    } else {
                        dbg[pos++] = '?';
                    }
                }
                dbg[pos] = '\0';
                OSTLS_LogLine(dbg);
            }

            sprintf(title_buf, "MacSSLTest -- A..C1 OK");
            sprintf(line1_buf, "%.140s", c1_msg);
            sprintf(line2_buf, "Req: %.140s", short_req);
            OSTLS_LogBlank();
            OSTLS_LogLine("==== ALL STAGES OK ====");
        } else {
            sprintf(title_buf, "MacSSLTest -- Stage C1 FAILED");
            sprintf(line1_buf, "Stage C1 FAILED (code %d): %.140s",
                (int)c1_result, c1_msg);
            sprintf(line2_buf, "Gate: %s (port=%u)",
                smoke_label(c1_result), (unsigned)OSTLS_C1_PORT);
            OSTLS_LogBlank();
            OSTLS_LogLinef("==== Stage C1 FAILED (code=%d) ====",
                           (int)c1_result);
        }
    }

    show_result_and_wait(title_buf, line1_buf, line2_buf);

    ostls_ot_close();
    OSTLS_LogClose();
    return 0;
}
