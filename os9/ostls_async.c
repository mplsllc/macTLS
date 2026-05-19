/*
 * ostls_async.c -- macSSL v0.2 non-blocking TLS stream API. See
 * os9/ostls_async.h for the public contract and
 * docs/macssl-v0.2-async-design.md for the design rationale.
 *
 * Architecture in one paragraph: every OT call goes through an
 * async dispatch path with a notifier installed at open time. The
 * notifier runs at interrupt time and just sets volatile flags on
 * the OSTLSConnection. OSTLS_Pump runs at app time, drains those
 * flags, advances the state machine, drives BearSSL one step at a
 * time, and shuttles bytes between BearSSL's record buffers and
 * the caller's plaintext ring buffers. No call blocks. No call
 * spins. The caller controls cadence by how often it invokes Pump
 * and with what max_steps budget.
 */

#include "ostls_async.h"
#include "ostls_b3_anchors.h"
#include "ostls_time.h"
#include "ostls_entropy.h"

#include "bearssl_ssl.h"
#include "bearssl_x509.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __MWERKS__
#include <Types.h>
#include <Memory.h>            /* NewPtrClear, DisposePtr */
#include <Events.h>            /* TickCount */
#include <Files.h>
#include <OpenTransport.h>
#include <OpenTptInternet.h>
extern OTClientContextPtr g_ostls_ot_context;
#else
/*
 * Non-CW8 Retro68 syntax-check stubs. Real linkage happens only on
 * CW8 against CarbonLib; these are enough to make the syntax check
 * happy on the Linux side.
 */
typedef long OTResult;
typedef long OTEventCode;
typedef void *EndpointRef;
typedef void *OTConfigurationRef;
typedef short OTByteCount;
typedef unsigned char UInt8;
typedef unsigned short InetPort;
typedef unsigned long InetHost;
#ifndef true
#define true 1
#define false 0
#endif
typedef int Boolean;
typedef struct { OTByteCount maxlen, len; UInt8 *buf; } TNetbuf;
typedef struct { TNetbuf addr; TNetbuf opt; long qlen; } TBind;
typedef struct { TNetbuf addr; TNetbuf opt; TNetbuf udata; long sequence; } TCall;
typedef struct { unsigned short fAddressType; char fName[1]; } DNSAddress;
typedef struct {
    unsigned short fAddressType;
    InetPort       fPort;
    InetHost       fHost;
    UInt8          fUnused[8];
} InetAddress;
typedef struct {
    long addr, options, tsdu, etsdu, connect, discon;
    long servtype, flags;
} TEndpointInfo;
typedef void (*OTNotifyProcPtr)(void *, OTEventCode, OTResult, void *);
/* `pascal` is already a Retro68 built-in calling-convention keyword;
 * do not redefine. */
#define noErr            0
#define kOTNoError       0
#define kOTNoDataErr  (-3162)
#define kOTFlowErr    (-3161)
#define kOTLookErr    (-3158)
#define T_OPENCOMPLETE  0x20000001L
#define T_BINDCOMPLETE  0x20000002L
#define T_CONNECT       0x00000002L
#define T_DATA          0x00000004L
#define T_EXDATA        0x00000008L
#define T_DISCONNECT    0x00000010L
#define T_ORDREL        0x00000080L
static OTConfigurationRef OTCreateConfiguration(const char *s){(void)s;return (OTConfigurationRef)1;}
static OSStatus OTAsyncOpenEndpointInContext(OTConfigurationRef c,unsigned long f,TEndpointInfo *i,OTNotifyProcPtr p,void *x,void *ctx){(void)c;(void)f;(void)i;(void)p;(void)x;(void)ctx;return noErr;}
static OSStatus OTBind(EndpointRef e,TBind *r,TBind *o){(void)e;(void)r;(void)o;return noErr;}
static OSStatus OTConnect(EndpointRef e,TCall *c,void *r){(void)e;(void)c;(void)r;return noErr;}
static OTResult OTSnd(EndpointRef e,void *b,long n,long f){(void)e;(void)b;(void)f;return n;}
static OTResult OTRcv(EndpointRef e,void *b,long n,long *f){(void)e;(void)b;(void)n;(void)f;return 0;}
static OSStatus OTSndOrderlyDisconnect(EndpointRef e){(void)e;return noErr;}
static OSStatus OTRcvOrderlyDisconnect(EndpointRef e){(void)e;return noErr;}
static OSStatus OTRcvDisconnect(EndpointRef e,void *p){(void)e;(void)p;return noErr;}
static OSStatus OTSndDisconnect(EndpointRef e,TCall *c){(void)e;(void)c;return noErr;}
static OSStatus OTRcvConnect(EndpointRef e,TCall *c){(void)e;(void)c;return noErr;}
static OTResult OTLook(EndpointRef e){(void)e;return 0;}
static OSStatus OTCloseProvider(EndpointRef e){(void)e;return noErr;}
static long OTInitDNSAddress(DNSAddress *d,const char *s){(void)d;(void)s;return 0;}
static void OTInitInetAddress(InetAddress *a, InetPort p, InetHost h){(void)a;(void)p;(void)h;}
static void OTMemzero(void *p,unsigned long n){memset(p,0,n);}
static char *NewPtrClear(unsigned long n){return (char *)calloc(1, n);}
static void DisposePtr(char *p){free(p);}
static unsigned long TickCount(void){return 0;}
extern void *g_ostls_ot_context;
#endif


/* ----------------------------------------------------------------- */
/* Internal connection structure                                     */
/* ----------------------------------------------------------------- */

#define OSTLS_READ_BUF_SIZE   4096
#define OSTLS_WRITE_BUF_SIZE  4096
#define OSTLS_DEFAULT_TIMEOUT 1800UL  /* 30s @ 60Hz */

/*
 * Internal phase markers for the connect sub-state machine. Visible
 * publicly only as kOSTLSStateConnecting; we track the substeps
 * here so Pump knows what notifier event to wait for next.
 */
enum {
    kConnectPhase_NeedsOpen     = 0,
    kConnectPhase_OpenInFlight  = 1,
    kConnectPhase_NeedsBind     = 2,
    kConnectPhase_BindInFlight  = 3,
    kConnectPhase_NeedsConnect  = 4,
    kConnectPhase_ConnectInFlight = 5,
    kConnectPhase_Done          = 6
};

struct OSTLSConnection {
    /* ----- Public-facing state ----- */
    OSTLSState state;
    OSErr      os_err;
    OSStatus   ot_err;
    int        br_err;
    UInt16     cipher_suite;

    /* ----- Caller-supplied config ----- */
    char    host[256];
    char    server_name[256];
    char    host_port[280];        /* "host:port" string for OTInitDNSAddress */
    UInt16  port;
    UInt32  connect_timeout_ticks;
    UInt32  handshake_timeout_ticks;
    void   *user_refcon;

    /* ----- Lifecycle bookkeeping ----- */
    UInt32  start_ticks;
    UInt32  handshake_start_ticks;
    int     connect_phase;          /* one of kConnectPhase_* */
    Boolean started;
    Boolean disposed;
    Boolean close_requested;        /* caller called OSTLS_Close */

    /* ----- OT machinery (stable buffers; outlive OT calls) ----- */
    EndpointRef ep;
    Boolean     ep_open;
    TEndpointInfo ep_info;
    DNSAddress  dns_addr;
    TBind       bind_req;
    TBind       bind_ret;
    InetAddress bound_addr;
    TCall       connect_call;
    Boolean     ord_consumed;       /* OTRcvOrderlyDisconnect called once */
    Boolean     disc_consumed;      /* OTRcvDisconnect called once */

    /* ----- Notifier-set flags (volatile; interrupt-time writes) ----- */
    volatile Boolean nf_open_complete;
    volatile Boolean nf_bind_complete;
    volatile Boolean nf_connect_complete;
    volatile Boolean nf_data_pending;
    volatile Boolean nf_ord_release;
    volatile Boolean nf_disconnect;
    volatile OTResult nf_last_result;

    /* ----- BearSSL ----- */
    br_ssl_client_context     sc;
    br_x509_minimal_context   xc;
    unsigned char             ssl_iobuf[BR_SSL_BUFSIZE_BIDI];
    Boolean                   bearssl_initialised;
    Boolean                   handshake_done;
    Boolean                   close_notify_sent;

    /* ----- Plaintext ring buffer (read side: BearSSL -> caller) ----- */
    unsigned char read_buf[OSTLS_READ_BUF_SIZE];
    UInt32        read_pos;
    UInt32        read_avail;

    /* ----- Plaintext queue (write side: caller -> BearSSL) ----- */
    unsigned char write_buf[OSTLS_WRITE_BUF_SIZE];
    UInt32        write_pos;
    UInt32        write_avail;

    /* ----- Diagnostic counters (exposed via OSTLS_GetDiagnostics) ----- */
    UInt32 dbg_ot_send_calls;
    UInt32 dbg_ot_send_bytes;
    UInt32 dbg_ot_send_zero;    /* OTSnd returned 0 (try again)        */
    UInt32 dbg_ot_send_flow;    /* OTSnd returned kOTFlowErr           */
    UInt32 dbg_ot_recv_calls;
    UInt32 dbg_ot_recv_bytes;
    UInt32 dbg_ot_recv_nodata;  /* OTRcv returned kOTNoDataErr         */
    UInt32 dbg_pump_calls;
    UInt32 br_state_last;       /* last br_ssl_engine_current_state    */
};


/* ----------------------------------------------------------------- */
/* Notifier                                                          */
/* ----------------------------------------------------------------- */

/*
 * Runs at INTERRUPT TIME. Strict constraints:
 *   - No memory allocation (no NewPtr / NewHandle / etc.)
 *   - No Toolbox calls (no logging, no UI)
 *   - Only OT calls documented as deferred-task-safe (OTRcvConnect)
 *
 * Touches only the volatile nf_* fields on the connection.
 */
static pascal void
ostls_notifier(void *context, OTEventCode event,
               OTResult result, void *cookie)
{
    OSTLSConnection *conn;

    conn = (OSTLSConnection *)context;
    if (conn == NULL) return;

    conn->nf_last_result = result;

    switch (event) {
    case T_OPENCOMPLETE:
        /* cookie is the new EndpointRef. Stash it for Pump to pick up. */
        conn->ep = (EndpointRef)cookie;
        conn->nf_open_complete = true;
        break;

    case T_BINDCOMPLETE:
        conn->nf_bind_complete = true;
        break;

    case T_CONNECT:
        /*
         * MUST consume the connect event before any later OT call on
         * this endpoint. OTRcvConnect is safe at interrupt time per
         * Apple OT documentation and Certainly's ot_transport.c
         * follows the same pattern.
         */
        OTRcvConnect(conn->ep, NULL);
        conn->nf_connect_complete = true;
        break;

    case T_DATA:
    case T_EXDATA:
        conn->nf_data_pending = true;
        break;

    case T_ORDREL:
        conn->nf_ord_release = true;
        break;

    case T_DISCONNECT:
        conn->nf_disconnect = true;
        break;

    default:
        /* Unhandled events are intentionally ignored; the only ones
         * we need for a TCP client+TLS path are above. */
        break;
    }
}


/* ----------------------------------------------------------------- */
/* Lifecycle: New / Dispose                                          */
/* ----------------------------------------------------------------- */

OSErr
OSTLS_New(OSTLSConnection **out_conn, const OSTLSConfig *config)
{
    OSTLSConnection *conn;
    size_t host_len;
    size_t sni_len;

    if (out_conn == NULL) {
        return (OSErr)kOSTLSAsync_BadArgs;
    }
    *out_conn = NULL;

    if (config == NULL || config->host == NULL ||
        config->server_name == NULL || config->port == 0) {
        return (OSErr)kOSTLSAsync_BadArgs;
    }

    host_len = strlen(config->host);
    sni_len  = strlen(config->server_name);
    if (host_len == 0 || host_len >= sizeof conn->host ||
        sni_len  == 0 || sni_len  >= sizeof conn->server_name) {
        return (OSErr)kOSTLSAsync_BadArgs;
    }

    conn = (OSTLSConnection *)NewPtrClear((unsigned long)sizeof *conn);
    if (conn == NULL) {
        return (OSErr)kOSTLSAsync_NoMemory;
    }

    /* NewPtrClear zeroes everything, but be explicit about the
     * fields that matter. */
    conn->state = kOSTLSStateIdle;
    conn->os_err = noErr;
    conn->ot_err = noErr;
    conn->br_err = 0;
    conn->cipher_suite = 0;

    memcpy(conn->host, config->host, host_len);
    conn->host[host_len] = '\0';
    memcpy(conn->server_name, config->server_name, sni_len);
    conn->server_name[sni_len] = '\0';
    conn->port = config->port;
    sprintf(conn->host_port, "%.250s:%u",
            conn->host, (unsigned)conn->port);
    conn->host_port[sizeof conn->host_port - 1] = '\0';

    conn->connect_timeout_ticks =
        (config->connect_timeout_ticks > 0)
        ? config->connect_timeout_ticks : OSTLS_DEFAULT_TIMEOUT;
    conn->handshake_timeout_ticks =
        (config->handshake_timeout_ticks > 0)
        ? config->handshake_timeout_ticks : OSTLS_DEFAULT_TIMEOUT;

    conn->user_refcon = config->user_refcon;

    conn->connect_phase = kConnectPhase_NeedsOpen;
    conn->started = false;
    conn->disposed = false;
    conn->close_requested = false;
    conn->ord_consumed = false;
    conn->disc_consumed = false;

    *out_conn = conn;
    return (OSErr)kOSTLSAsync_OK;
}


void
OSTLS_Dispose(OSTLSConnection *conn)
{
    if (conn == NULL) return;
    if (conn->disposed) return;

    /* If we still have an OT endpoint, tear it down. We don't care
     * whether the caller called Close first -- Dispose is the
     * final teardown regardless of state. */
    if (conn->ep_open && conn->ep != NULL) {
        /* If we're mid-connection, an orderly disconnect attempt is
         * harmless. If we're already torn down, OT will return an
         * error which we ignore here. */
        OTSndOrderlyDisconnect(conn->ep);
        OTCloseProvider(conn->ep);
        conn->ep = NULL;
        conn->ep_open = false;
    }

    conn->disposed = true;
    DisposePtr((char *)conn);
}


/* ----------------------------------------------------------------- */
/* Lifecycle: Start                                                  */
/* ----------------------------------------------------------------- */

OSErr
OSTLS_Start(OSTLSConnection *conn)
{
    OTConfigurationRef cfg;
    OSStatus oterr;
    OSErr time_err;
    UInt32 br_days;
    UInt32 br_seconds;

    if (conn == NULL || conn->disposed) {
        return (OSErr)kOSTLSAsync_BadArgs;
    }
    if (conn->started) {
        return (OSErr)kOSTLSAsync_WrongState;
    }
    if (conn->state != kOSTLSStateIdle) {
        return (OSErr)kOSTLSAsync_WrongState;
    }

    /* Validate the system clock before we kick off any TLS work --
     * a pre-2000 clock will make every cert fail validation later
     * and the user will see a useless "handshake failed" instead
     * of an actionable "set your clock" message. */
    time_err = OSTLS_GetBearSSLTime(&br_days, &br_seconds);
    if (time_err == kOSTLSTimeClockBefore2000) {
        conn->state = kOSTLSStateFailed;
        conn->os_err = (OSErr)kOSTLSAsync_ClockBefore2000;
        return (OSErr)kOSTLSAsync_ClockBefore2000;
    }
    if (time_err != kOSTLSTimeOK) {
        conn->state = kOSTLSStateFailed;
        conn->os_err = (OSErr)kOSTLSAsync_ClockBefore2000;
        return (OSErr)kOSTLSAsync_ClockBefore2000;
    }

    cfg = OTCreateConfiguration("tcp");
    if (cfg == NULL || cfg == (OTConfigurationRef)-1L) {
        conn->state = kOSTLSStateFailed;
        conn->os_err = (OSErr)kOSTLSAsync_OTConfigFail;
        return (OSErr)kOSTLSAsync_OTConfigFail;
    }

    /*
     * Async open: returns immediately. T_OPENCOMPLETE will fire on
     * the notifier when the endpoint is ready; that handler stashes
     * the EndpointRef into conn->ep.
     */
    OTMemzero(&conn->ep_info, sizeof conn->ep_info);
    oterr = OTAsyncOpenEndpointInContext(cfg, 0, &conn->ep_info,
                                         (OTNotifyProcPtr)ostls_notifier,
                                         conn,
                                         g_ostls_ot_context);
    if (oterr != noErr) {
        conn->state = kOSTLSStateFailed;
        conn->os_err = (OSErr)kOSTLSAsync_OTOpenFail;
        conn->ot_err = oterr;
        return (OSErr)kOSTLSAsync_OTOpenFail;
    }

    conn->state = kOSTLSStateConnecting;
    conn->connect_phase = kConnectPhase_OpenInFlight;
    conn->start_ticks = (UInt32)TickCount();
    conn->started = true;

    return (OSErr)kOSTLSAsync_OK;
}


/* ----------------------------------------------------------------- */
/* Pump helpers                                                      */
/* ----------------------------------------------------------------- */

/*
 * Set the connection to Failed with the given codes. Idempotent.
 * Returns the kOSTLSEventFailed value so callers can chain
 *   *event = ostls_fail(conn, ...);
 */
static OSTLSEvent
ostls_fail(OSTLSConnection *conn, OSErr os_err,
           OSStatus ot_err, int br_err)
{
    if (conn->state == kOSTLSStateFailed ||
        conn->state == kOSTLSStateClosed) {
        return kOSTLSEventNone;
    }
    conn->state = kOSTLSStateFailed;
    if (conn->os_err == noErr) conn->os_err = os_err;
    if (ot_err != noErr && conn->ot_err == noErr) conn->ot_err = ot_err;
    if (br_err != 0 && conn->br_err == 0) conn->br_err = br_err;
    return kOSTLSEventFailed;
}


/*
 * Bump `best_event` only if `candidate` has higher precedence.
 * Precedence order (high to low): Failed > Closed > HandshakeDone
 * > Connected > Readable > Writable > None.
 */
static int
event_priority(OSTLSEvent e)
{
    switch (e) {
    case kOSTLSEventFailed:        return 7;
    case kOSTLSEventClosed:        return 6;
    case kOSTLSEventHandshakeDone: return 5;
    case kOSTLSEventConnected:     return 4;
    case kOSTLSEventReadable:      return 3;
    case kOSTLSEventWritable:      return 2;
    case kOSTLSEventNone:          return 0;
    }
    return 0;
}


static void
event_bump(OSTLSEvent *current, OSTLSEvent candidate)
{
    if (event_priority(candidate) > event_priority(*current)) {
        *current = candidate;
    }
}


/*
 * Initialise BearSSL on this connection after the TCP connect has
 * completed. Once-per-connection setup.
 */
static OSTLSEvent
ostls_setup_bearssl(OSTLSConnection *conn)
{
    const br_x509_trust_anchor *anchors;
    size_t anchors_count;
    UInt32 br_days;
    UInt32 br_seconds;
    OSErr time_err;
    int entropy_err;
    int reset_ok;

    /* Re-read the clock; the user could have ticked over midnight
     * between Start and the first handshake step (unlikely on a
     * fresh connect, but defensive). */
    time_err = OSTLS_GetBearSSLTime(&br_days, &br_seconds);
    if (time_err != kOSTLSTimeOK) {
        return ostls_fail(conn, (OSErr)kOSTLSAsync_ClockBefore2000,
                          noErr, 0);
    }

    OSTLS_B3_GetAnchors(&anchors, &anchors_count);
    br_ssl_client_init_full(&conn->sc, &conn->xc,
                            anchors, anchors_count);
    br_x509_minimal_set_time(&conn->xc, br_days, br_seconds);

    entropy_err = OSTLS_InjectStageAEntropy(&conn->sc.eng);
    if (entropy_err != 0) {
        return ostls_fail(conn, (OSErr)kOSTLSAsync_EntropyFail,
                          noErr, 0);
    }

    br_ssl_engine_set_buffer(&conn->sc.eng,
                             conn->ssl_iobuf,
                             sizeof conn->ssl_iobuf, 1);

    reset_ok = br_ssl_client_reset(&conn->sc, conn->server_name, 0);
    if (reset_ok == 0) {
        int br_err = br_ssl_engine_last_error(&conn->sc.eng);
        return ostls_fail(conn, (OSErr)kOSTLSAsync_ClientResetFail,
                          noErr, br_err);
    }

    conn->bearssl_initialised = true;
    conn->handshake_start_ticks = (UInt32)TickCount();
    return kOSTLSEventNone;
}


/*
 * Advance the connect phase by one step. Returns the event observed
 * (if any) and increments *steps_used by 1 if it did something.
 */
static OSTLSEvent
pump_connect_step(OSTLSConnection *conn, UInt32 *steps_used)
{
    OSStatus oterr;
    long dns_len;
    UInt32 now;

    now = (UInt32)TickCount();
    if (now - conn->start_ticks > conn->connect_timeout_ticks) {
        return ostls_fail(conn, (OSErr)kOSTLSAsync_ConnectTimeout,
                          noErr, 0);
    }

    if (conn->nf_disconnect) {
        conn->nf_disconnect = false;
        return ostls_fail(conn, (OSErr)kOSTLSAsync_OTConnectFail,
                          conn->nf_last_result, 0);
    }

    switch (conn->connect_phase) {
    case kConnectPhase_OpenInFlight:
        if (!conn->nf_open_complete) return kOSTLSEventNone;
        conn->nf_open_complete = false;
        if (conn->nf_last_result != noErr) {
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTOpenFail,
                              conn->nf_last_result, 0);
        }
        if (conn->ep == NULL) {
            /* Shouldn't happen if T_OPENCOMPLETE arrived with
             * noErr, but be defensive. */
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTOpenFail,
                              -1, 0);
        }
        conn->ep_open = true;
        conn->connect_phase = kConnectPhase_NeedsBind;
        (*steps_used)++;
        return kOSTLSEventNone;

    case kConnectPhase_NeedsBind:
        /*
         * Outbound client bind: addr=NULL, qlen=0. Verified safe in
         * v0.1 (B1-B4 all use this exact form) and explicitly NOT
         * the broken Carbon CFM caller-chosen-address case.
         */
        OTMemzero(&conn->bind_req, sizeof conn->bind_req);
        OTMemzero(&conn->bind_ret, sizeof conn->bind_ret);
        oterr = OTBind(conn->ep, NULL, NULL);
        if (oterr != noErr && oterr != kOTNoError) {
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTBindFail,
                              oterr, 0);
        }
        conn->connect_phase = kConnectPhase_BindInFlight;
        (*steps_used)++;
        return kOSTLSEventNone;

    case kConnectPhase_BindInFlight:
        if (!conn->nf_bind_complete) return kOSTLSEventNone;
        conn->nf_bind_complete = false;
        if (conn->nf_last_result != noErr) {
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTBindFail,
                              conn->nf_last_result, 0);
        }
        conn->connect_phase = kConnectPhase_NeedsConnect;
        (*steps_used)++;
        return kOSTLSEventNone;

    case kConnectPhase_NeedsConnect:
        /* Build the connect address from host:port via DNSAddress. */
        OTMemzero(&conn->dns_addr, sizeof conn->dns_addr);
        OTMemzero(&conn->connect_call, sizeof conn->connect_call);
        dns_len = OTInitDNSAddress(&conn->dns_addr,
                                   (char *)conn->host_port);
        if (dns_len <= 0) {
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTConnectFail,
                              dns_len, 0);
        }
        conn->connect_call.addr.buf = (UInt8 *)&conn->dns_addr;
        conn->connect_call.addr.len = (short)dns_len;
        oterr = OTConnect(conn->ep, &conn->connect_call, NULL);
        if (oterr != noErr && oterr != kOTNoError &&
            oterr != kOTNoDataErr) {
            /* kOTNoDataErr after an async OTConnect means "in
             * flight" -- that's expected. Any other error is
             * fatal. */
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTConnectFail,
                              oterr, 0);
        }
        conn->connect_phase = kConnectPhase_ConnectInFlight;
        (*steps_used)++;
        return kOSTLSEventNone;

    case kConnectPhase_ConnectInFlight:
        if (!conn->nf_connect_complete) return kOSTLSEventNone;
        conn->nf_connect_complete = false;
        if (conn->nf_last_result != noErr) {
            return ostls_fail(conn, (OSErr)kOSTLSAsync_OTConnectFail,
                              conn->nf_last_result, 0);
        }
        conn->connect_phase = kConnectPhase_Done;
        /* Transition to handshaking. */
        conn->state = kOSTLSStateHandshaking;
        {
            OSTLSEvent setup_ev = ostls_setup_bearssl(conn);
            if (setup_ev == kOSTLSEventFailed) return kOSTLSEventFailed;
        }
        (*steps_used)++;
        return kOSTLSEventConnected;

    default:
        return kOSTLSEventNone;
    }
}


/*
 * Read up to one OTRcv worth of bytes from the wire and hand them
 * to BearSSL's recvrec buffer. Returns 1 if work was done, 0 if no
 * data was available, -1 on terminal failure (connection moved to
 * Failed/Closed).
 */
static int
pump_ot_recv_into_bearssl(OSTLSConnection *conn)
{
    unsigned char *rbuf;
    size_t rlen;
    OTResult got;

    rbuf = br_ssl_engine_recvrec_buf(&conn->sc.eng, &rlen);
    if (rlen == 0) return 0;

    got = OTRcv(conn->ep, rbuf, (long)rlen, NULL);
    conn->dbg_ot_recv_calls++;
    if (got > 0) {
        br_ssl_engine_recvrec_ack(&conn->sc.eng, (size_t)got);
        conn->nf_data_pending = false;  /* drained for now */
        conn->dbg_ot_recv_bytes += (UInt32)got;
        return 1;
    }
    if (got == 0) {
        /* Peer closed; BearSSL will see this as an unexpected close. */
        conn->nf_data_pending = false;
        return 0;
    }
    if (got == kOTNoDataErr) {
        conn->nf_data_pending = false;
        conn->dbg_ot_recv_nodata++;
        return 0;
    }
    if (got == kOTLookErr) {
        /* An OT event arrived between OTRcv and now. Drain it next
         * tick. */
        return 0;
    }
    /* Real error. */
    ostls_fail(conn, (OSErr)kOSTLSAsync_OTRcvFail, got, 0);
    return -1;
}


/*
 * Push whatever BearSSL has queued to send onto the wire. Returns
 * 1 if work was done, 0 if nothing to send, -1 on terminal failure.
 */
static int
pump_ot_send_from_bearssl(OSTLSConnection *conn)
{
    unsigned char *sbuf;
    size_t slen;
    OTResult sent;

    sbuf = br_ssl_engine_sendrec_buf(&conn->sc.eng, &slen);
    if (slen == 0) return 0;

    sent = OTSnd(conn->ep, sbuf, (long)slen, 0);
    conn->dbg_ot_send_calls++;
    if (sent >= 0) {
        if ((size_t)sent > 0) {
            br_ssl_engine_sendrec_ack(&conn->sc.eng, (size_t)sent);
            conn->dbg_ot_send_bytes += (UInt32)sent;
            return 1;
        }
        conn->dbg_ot_send_zero++;
        return 0;
    }
    if (sent == kOTFlowErr) {
        /* OT send buffer full; try again next tick. */
        conn->dbg_ot_send_flow++;
        return 0;
    }
    if (sent == kOTLookErr) {
        return 0;
    }
    ostls_fail(conn, (OSErr)kOSTLSAsync_OTSndFail, sent, 0);
    return -1;
}


/*
 * Copy decrypted bytes from BearSSL's recvapp buffer into the
 * connection's internal read ring. Back-pressure: if the ring
 * is full, we don't ack BearSSL, which causes its recvapp_buf to
 * stay non-empty, which eventually halts further record decoding,
 * which closes the TCP receive window on the peer. Caller must
 * Read promptly.
 */
static int
pump_bearssl_recvapp_to_ring(OSTLSConnection *conn,
                             OSTLSEvent *best_event)
{
    unsigned char *abuf;
    size_t alen;
    UInt32 room;
    UInt32 free_at_end;
    size_t to_copy;

    abuf = br_ssl_engine_recvapp_buf(&conn->sc.eng, &alen);
    if (alen == 0) return 0;

    if (conn->read_avail >= sizeof conn->read_buf) {
        /* Ring is full; back-pressure to BearSSL. */
        return 0;
    }
    room = (UInt32)sizeof conn->read_buf - conn->read_avail;

    /*
     * The read buffer is a logical ring but we keep it linear:
     * read_pos is the next-byte-to-give-caller index, read_avail
     * is the count of bytes after that. To accept new bytes we
     * write at (read_pos + read_avail) mod sizeof. For a 4 KB
     * buffer with typical chunk sizes the wrap doesn't bite often;
     * we handle it explicitly below.
     */
    {
        UInt32 write_idx = (conn->read_pos + conn->read_avail)
            % (UInt32)sizeof conn->read_buf;
        free_at_end = (UInt32)sizeof conn->read_buf - write_idx;
        if (free_at_end > room) free_at_end = room;
        to_copy = alen;
        if ((UInt32)to_copy > free_at_end) {
            to_copy = (size_t)free_at_end;
        }
        memcpy(conn->read_buf + write_idx, abuf, to_copy);
        conn->read_avail += (UInt32)to_copy;
    }
    br_ssl_engine_recvapp_ack(&conn->sc.eng, to_copy);

    event_bump(best_event, kOSTLSEventReadable);
    return 1;
}


/*
 * Move bytes from the caller's write queue into BearSSL's sendapp
 * buffer. Returns 1 if any work happened.
 */
static int
pump_ring_to_bearssl_sendapp(OSTLSConnection *conn,
                             OSTLSEvent *best_event)
{
    unsigned char *abuf;
    size_t alen;
    size_t to_copy;

    if (conn->write_avail == 0) return 0;

    abuf = br_ssl_engine_sendapp_buf(&conn->sc.eng, &alen);
    if (alen == 0) return 0;

    to_copy = conn->write_avail;
    if (to_copy > alen) to_copy = alen;

    memcpy(abuf, conn->write_buf + conn->write_pos, to_copy);
    br_ssl_engine_sendapp_ack(&conn->sc.eng, to_copy);
    conn->write_pos += (UInt32)to_copy;
    conn->write_avail -= (UInt32)to_copy;
    if (conn->write_avail == 0) {
        conn->write_pos = 0;
        br_ssl_engine_flush(&conn->sc.eng, 0);
        event_bump(best_event, kOSTLSEventWritable);
    }
    return 1;
}


/*
 * Advance BearSSL by exactly one record-pump step. Looks at the
 * engine state and does the single most-useful action available:
 * sendrec, recvrec, sendapp, or recvapp.
 */
static int
pump_bearssl_step(OSTLSConnection *conn, OSTLSEvent *best_event)
{
    unsigned state;
    int br_err;

    state = br_ssl_engine_current_state(&conn->sc.eng);

    if ((state & BR_SSL_CLOSED) != 0) {
        br_err = br_ssl_engine_last_error(&conn->sc.eng);
        if (br_err == BR_ERR_OK) {
            /* Clean close. Drain any buffered plaintext first. */
            if (conn->state == kOSTLSStateOpen ||
                conn->state == kOSTLSStateClosing) {
                conn->state = kOSTLSStateClosed;
                event_bump(best_event, kOSTLSEventClosed);
            } else {
                /* Closed before handshake finished. */
                ostls_fail(conn, (OSErr)kOSTLSAsync_PeerClosed,
                           noErr, 0);
                *best_event = kOSTLSEventFailed;
            }
        } else {
            ostls_fail(conn, (OSErr)kOSTLSAsync_BearSSLError,
                       noErr, br_err);
            *best_event = kOSTLSEventFailed;
        }
        return 1;
    }

    /* Handshake just completed? */
    if (!conn->handshake_done &&
        conn->state == kOSTLSStateHandshaking &&
        (state & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) != 0) {
        const br_ssl_session_parameters *sess;
        conn->handshake_done = true;
        conn->state = kOSTLSStateOpen;
        sess = &conn->sc.eng.session;
        conn->cipher_suite =
            (UInt16)(sess->cipher_suite & 0xFFFFU);
        event_bump(best_event, kOSTLSEventHandshakeDone);
        return 1;
    }

    if ((state & BR_SSL_SENDREC) != 0) {
        return pump_ot_send_from_bearssl(conn);
    }
    if ((state & BR_SSL_RECVREC) != 0) {
        return pump_ot_recv_into_bearssl(conn);
    }
    if (conn->state == kOSTLSStateOpen) {
        if ((state & BR_SSL_RECVAPP) != 0) {
            return pump_bearssl_recvapp_to_ring(conn, best_event);
        }
        if (conn->write_avail > 0 &&
            (state & BR_SSL_SENDAPP) != 0) {
            return pump_ring_to_bearssl_sendapp(conn, best_event);
        }
    }
    return 0;
}


/*
 * Handshake-phase timeout. Should the orderly-release event have
 * arrived during connect or handshake, that's also an early-close.
 */
static OSTLSEvent
pump_handshake_or_open_pre(OSTLSConnection *conn)
{
    UInt32 now;

    if (conn->state == kOSTLSStateHandshaking) {
        now = (UInt32)TickCount();
        if (now - conn->handshake_start_ticks >
            conn->handshake_timeout_ticks) {
            return ostls_fail(conn,
                (OSErr)kOSTLSAsync_HandshakeTimeout, noErr, 0);
        }
    }
    if (conn->nf_ord_release && !conn->ord_consumed) {
        OTRcvOrderlyDisconnect(conn->ep);
        conn->ord_consumed = true;
        /* Don't transition state yet; let any remaining plaintext
         * drain via BearSSL CLOSED handling above. */
    }
    return kOSTLSEventNone;
}


/* ----------------------------------------------------------------- */
/* OSTLS_Pump                                                        */
/* ----------------------------------------------------------------- */

OSErr
OSTLS_Pump(OSTLSConnection *conn, UInt32 max_steps, OSTLSEvent *out_event)
{
    OSTLSEvent best_event;
    UInt32 steps_used;

    if (out_event != NULL) *out_event = kOSTLSEventNone;
    if (conn == NULL) return (OSErr)kOSTLSAsync_BadArgs;
    if (conn->disposed) return (OSErr)kOSTLSAsync_Disposed;

    conn->dbg_pump_calls++;
    if (conn->bearssl_initialised) {
        conn->br_state_last =
            (UInt32)br_ssl_engine_current_state(&conn->sc.eng);
    }

    best_event = kOSTLSEventNone;
    steps_used = 0;

    /* Terminal-state fast paths: still report the event one time
     * each, with no work. */
    if (conn->state == kOSTLSStateFailed) {
        if (out_event != NULL) *out_event = kOSTLSEventFailed;
        return noErr;
    }
    if (conn->state == kOSTLSStateClosed) {
        if (out_event != NULL) {
            *out_event = (conn->read_avail > 0)
                ? kOSTLSEventReadable
                : kOSTLSEventClosed;
        }
        return noErr;
    }
    if (max_steps == 0) {
        return noErr;
    }

    while (steps_used < max_steps) {
        OSTLSEvent step_ev;

        if (conn->state == kOSTLSStateFailed ||
            conn->state == kOSTLSStateClosed) {
            break;
        }

        /* Pre-step bookkeeping: timeouts, orderly-release. */
        step_ev = pump_handshake_or_open_pre(conn);
        if (step_ev == kOSTLSEventFailed) {
            event_bump(&best_event, kOSTLSEventFailed);
            break;
        }

        if (conn->state == kOSTLSStateConnecting) {
            UInt32 before = steps_used;
            step_ev = pump_connect_step(conn, &steps_used);
            event_bump(&best_event, step_ev);
            if (steps_used == before) {
                /* No progress this iteration; nothing to do until
                 * the next notifier callback. */
                break;
            }
            continue;
        }

        if (conn->state == kOSTLSStateHandshaking ||
            conn->state == kOSTLSStateOpen ||
            conn->state == kOSTLSStateClosing) {
            int did = pump_bearssl_step(conn, &best_event);
            if (did <= 0) {
                /* Nothing more to do this slice. */
                break;
            }
            steps_used++;
            continue;
        }

        break;
    }

    if (out_event != NULL) *out_event = best_event;
    return noErr;
}


/* ----------------------------------------------------------------- */
/* OSTLS_Write / OSTLS_Read                                          */
/* ----------------------------------------------------------------- */

OSErr
OSTLS_Write(OSTLSConnection *conn, const void *buf,
            UInt32 len, UInt32 *out_written)
{
    UInt32 free_room;
    UInt32 to_copy;

    if (out_written != NULL) *out_written = 0;
    if (conn == NULL || buf == NULL) {
        return (OSErr)kOSTLSAsync_BadArgs;
    }
    if (conn->disposed) return (OSErr)kOSTLSAsync_Disposed;
    if (conn->state != kOSTLSStateOpen) {
        return (OSErr)kOSTLSAsync_WrongState;
    }
    if (len == 0) return noErr;

    /*
     * Append to the linear write_buf. We compact when write_avail
     * drains to 0 (in pump_ring_to_bearssl_sendapp). If there's
     * stale write_pos > 0 and write_avail > 0, compact now to
     * make room.
     */
    if (conn->write_pos > 0 && conn->write_avail > 0) {
        memmove(conn->write_buf,
                conn->write_buf + conn->write_pos,
                conn->write_avail);
        conn->write_pos = 0;
    }
    free_room = (UInt32)sizeof conn->write_buf - conn->write_avail;
    to_copy = (len < free_room) ? len : free_room;
    if (to_copy == 0) {
        /* Buffer full; tell the caller to retry after Pump. */
        return noErr;
    }
    memcpy(conn->write_buf + conn->write_avail,
           buf, to_copy);
    conn->write_avail += to_copy;
    if (out_written != NULL) *out_written = to_copy;
    return noErr;
}


OSErr
OSTLS_Read(OSTLSConnection *conn, void *buf,
           UInt32 cap, UInt32 *out_read)
{
    UInt32 first_chunk;
    UInt32 second_chunk;
    UInt32 to_copy;
    UInt32 ring_size;

    if (out_read != NULL) *out_read = 0;
    if (conn == NULL || buf == NULL) {
        return (OSErr)kOSTLSAsync_BadArgs;
    }
    if (conn->disposed) return (OSErr)kOSTLSAsync_Disposed;
    if (conn->state != kOSTLSStateOpen &&
        conn->state != kOSTLSStateClosing &&
        conn->state != kOSTLSStateClosed) {
        return (OSErr)kOSTLSAsync_WrongState;
    }
    if (cap == 0) return noErr;
    if (conn->read_avail == 0) return noErr;

    ring_size = (UInt32)sizeof conn->read_buf;
    to_copy = conn->read_avail;
    if (to_copy > cap) to_copy = cap;

    /* The ring may wrap; copy in up to two chunks. */
    first_chunk = ring_size - conn->read_pos;
    if (first_chunk > to_copy) first_chunk = to_copy;
    memcpy(buf, conn->read_buf + conn->read_pos, first_chunk);
    second_chunk = to_copy - first_chunk;
    if (second_chunk > 0) {
        memcpy((unsigned char *)buf + first_chunk,
               conn->read_buf,
               second_chunk);
    }
    conn->read_pos = (conn->read_pos + to_copy) % ring_size;
    conn->read_avail -= to_copy;
    if (out_read != NULL) *out_read = to_copy;
    return noErr;
}


/* ----------------------------------------------------------------- */
/* OSTLS_Close                                                       */
/* ----------------------------------------------------------------- */

void
OSTLS_Close(OSTLSConnection *conn)
{
    if (conn == NULL || conn->disposed) return;
    if (conn->close_requested) return;
    conn->close_requested = true;

    if (conn->state == kOSTLSStateClosed ||
        conn->state == kOSTLSStateFailed) {
        return;
    }

    if (conn->state == kOSTLSStateHandshaking ||
        conn->state == kOSTLSStateConnecting) {
        /* Mid-handshake close: hard disconnect; can't gracefully
         * close_notify because the session isn't established. */
        if (conn->ep_open && conn->ep != NULL) {
            OTSndDisconnect(conn->ep, NULL);
        }
        conn->state = kOSTLSStateFailed;
        conn->os_err = (OSErr)kOSTLSAsync_WrongState;
        return;
    }

    if (conn->state == kOSTLSStateOpen ||
        conn->state == kOSTLSStateClosing) {
        if (!conn->close_notify_sent) {
            br_ssl_engine_close(&conn->sc.eng);
            conn->close_notify_sent = true;
        }
        conn->state = kOSTLSStateClosing;
        /* The next few Pumps will drain the close_notify out and
         * transition to Closed naturally. */
    }
}


/* ----------------------------------------------------------------- */
/* Introspection                                                     */
/* ----------------------------------------------------------------- */

OSTLSState
OSTLS_GetState(OSTLSConnection *conn)
{
    if (conn == NULL || conn->disposed) return kOSTLSStateFailed;
    return conn->state;
}

OSErr
OSTLS_GetLastError(OSTLSConnection *conn)
{
    if (conn == NULL) return (OSErr)kOSTLSAsync_BadArgs;
    if (conn->disposed) return (OSErr)kOSTLSAsync_Disposed;
    return conn->os_err;
}

UInt16
OSTLS_GetCipherSuite(OSTLSConnection *conn)
{
    if (conn == NULL || conn->disposed) return 0;
    return conn->cipher_suite;
}

void
OSTLS_GetDiagnostics(OSTLSConnection *conn,
                     OSTLSDiagnostics *out_diag)
{
    if (out_diag == NULL) return;
    if (conn == NULL || conn->disposed) {
        out_diag->os_err         = (OSErr)kOSTLSAsync_Disposed;
        out_diag->ot_err         = noErr;
        out_diag->br_err         = 0;
        out_diag->state          = kOSTLSStateFailed;
        out_diag->cipher_suite   = 0;
        out_diag->ot_send_calls  = 0;
        out_diag->ot_send_bytes  = 0;
        out_diag->ot_send_zero   = 0;
        out_diag->ot_send_flow   = 0;
        out_diag->ot_recv_calls  = 0;
        out_diag->ot_recv_bytes  = 0;
        out_diag->ot_recv_nodata = 0;
        out_diag->pump_calls     = 0;
        out_diag->br_state_last  = 0;
        return;
    }
    out_diag->os_err         = conn->os_err;
    out_diag->ot_err         = conn->ot_err;
    out_diag->br_err         = conn->br_err;
    out_diag->state          = conn->state;
    out_diag->cipher_suite   = conn->cipher_suite;
    out_diag->ot_send_calls  = conn->dbg_ot_send_calls;
    out_diag->ot_send_bytes  = conn->dbg_ot_send_bytes;
    out_diag->ot_send_zero   = conn->dbg_ot_send_zero;
    out_diag->ot_send_flow   = conn->dbg_ot_send_flow;
    out_diag->ot_recv_calls  = conn->dbg_ot_recv_calls;
    out_diag->ot_recv_bytes  = conn->dbg_ot_recv_bytes;
    out_diag->ot_recv_nodata = conn->dbg_ot_recv_nodata;
    out_diag->pump_calls     = conn->dbg_pump_calls;
    out_diag->br_state_last  = conn->br_state_last;
}

void *
OSTLS_GetUserRefcon(OSTLSConnection *conn)
{
    if (conn == NULL || conn->disposed) return NULL;
    return conn->user_refcon;
}
