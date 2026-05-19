/*
 * ostls_c1_listener.c -- Stage C1 OT TCP listener probe. See header.
 *
 * OT server pattern (synchronous + blocking):
 *
 *   1. listener = OTOpenEndpointInContext("tcp", ...)
 *   2. OTSetSynchronous / OTSetBlocking
 *   3. OTInitInetAddress(&addr, port, 0)  -- 0 = INADDR_ANY
 *   4. TBind req = { .qlen = 1, .addr = { &addr, sizeof addr } }
 *      OTBind(listener, &req, NULL)
 *   5. TCall call = { .addr = { peer_addr_buf, sizeof peer_addr_buf } }
 *      OTListen(listener, &call)     -- blocks until peer arrives
 *   6. child = OTOpenEndpointInContext("tcp", ...)
 *   7. OTBind(child, NULL, NULL)    -- ephemeral local addr
 *   8. OTAccept(listener, child, &call)
 *   9. OTRcv(child, buf, len, NULL) repeatedly until 0 or buf full
 *  10. OTSndOrderlyDisconnect / OTCloseProvider on both endpoints
 *
 * The InetAddress and TBind structs come from OpenTptInternet.h.
 * 0.0.0.0:port is the safest INADDR_ANY equivalent on classic OT;
 * binding strictly to 127.0.0.1 is unreliable across OT versions.
 * Firewalls and AppleTalk filters are the operator's concern.
 */

#include "ostls_c1_listener.h"
#include "ostls_log.h"

#include <stdio.h>
#include <string.h>

#ifdef __MWERKS__
#include <Files.h>
#include <OpenTransport.h>
#include <OpenTptInternet.h>
extern OTClientContextPtr g_ostls_ot_context;
#else
/* Non-CW8 syntax-check stubs. */
typedef long OSStatus;
typedef long OTResult;
typedef void *EndpointRef;
typedef void *OTConfigurationRef;
typedef short OTByteCount;
typedef unsigned char UInt8;
typedef unsigned short InetPort;
typedef unsigned long InetHost;
typedef struct { OTByteCount maxlen, len; UInt8 *buf; } TNetbuf;
typedef struct { TNetbuf addr; TNetbuf opt; long qlen; } TBind;
typedef struct { TNetbuf addr; TNetbuf opt; TNetbuf udata; long sequence; } TCall;
typedef struct {
    long addr, options, tsdu, etsdu, connect, discon;
    long servtype, flags, qlen;
} TEndpointInfo;
typedef struct {
    unsigned short fAddressType;
    InetPort       fPort;
    InetHost       fHost;
    char           fUnused[8];
} InetAddress;
#define noErr 0
#define AF_INET 2
#define kAFInet AF_INET
static OTConfigurationRef OTCreateConfiguration(const char *s){(void)s;return (OTConfigurationRef)1;}
static EndpointRef OTOpenEndpointInContext(OTConfigurationRef c,unsigned long f,void *p,OSStatus *e,void *x){(void)c;(void)f;(void)p;(void)x;*e=noErr;return (EndpointRef)1;}
static OSStatus OTSetSynchronous(EndpointRef e){(void)e;return noErr;}
static OSStatus OTSetBlocking(EndpointRef e){(void)e;return noErr;}
static OSStatus OTBind(EndpointRef e,TBind *r,TBind *o){(void)e;(void)r;(void)o;return noErr;}
static OSStatus OTListen(EndpointRef e,TCall *c){(void)e;(void)c;return noErr;}
static OSStatus OTAccept(EndpointRef l,EndpointRef c,TCall *call){(void)l;(void)c;(void)call;return noErr;}
static OTResult OTRcv(EndpointRef e,void *b,long n,long *f){(void)e;(void)b;(void)n;(void)f;return 0;}
static OSStatus OTSndOrderlyDisconnect(EndpointRef e){(void)e;return noErr;}
static OSStatus OTCloseProvider(EndpointRef e){(void)e;return noErr;}
static void OTInitInetAddress(InetAddress *a, InetPort p, InetHost h){(void)a;(void)p;(void)h;}
static void OTMemzero(void *p,unsigned long n){memset(p,0,n);}
extern void *g_ostls_ot_context;
#endif


/* ----------------------------------------------------------------- */
/* Status helper                                                     */
/* ----------------------------------------------------------------- */

static void
c1_status(char *out, size_t out_len, const char *prefix, long err)
{
    if (out == NULL || out_len < 4) {
        return;
    }
    if (err == 0) {
        sprintf(out, "%.140s", prefix);
    } else {
        sprintf(out, "%.110s (err=%ld)", prefix, err);
    }
    out[out_len - 1] = '\0';
}


/* ----------------------------------------------------------------- */
/* Probe                                                             */
/* ----------------------------------------------------------------- */

OSErr
OSTLS_C1_Listener_Probe(unsigned short port,
                        char *out_request, size_t out_request_cap,
                        char *out_msg, size_t out_msg_len)
{
    OTConfigurationRef cfg_listener;
    OTConfigurationRef cfg_child;
    EndpointRef listener_ep;
    EndpointRef child_ep;
    OSStatus oterr;
    InetAddress local_addr;
    InetAddress peer_addr;
    TBind bind_req;
    TCall call;
    size_t received;
    OTResult got;

    if (out_request == NULL || out_request_cap < 2 || port == 0) {
        c1_status(out_msg, out_msg_len, "C1: bad args", 0);
        return (OSErr)kOSTLSC1_BadArgs;
    }
    out_request[0] = '\0';
    received = 0;

    /* ----- 1. Open listener endpoint -----
     *
     * The protocol-stack string for a TCP LISTENER must include the
     * "tilisten" module on top of "tcp". Plain "tcp" gives you an
     * outbound (client) endpoint; OTBind with qlen >= 1 against a
     * plain "tcp" endpoint returns kOTBadAddressErr (-3150) because
     * the underlying provider has no passive-open semantics. The
     * tilisten module wraps tcp with listen / accept primitives.
     *
     * Outbound endpoints elsewhere in this project (B1, B2, B3, B4)
     * correctly use just "tcp" because they only OTConnect.
     */
    cfg_listener = OTCreateConfiguration("tilisten,tcp");
    if (cfg_listener == NULL || cfg_listener == (OTConfigurationRef)-1L) {
        c1_status(out_msg, out_msg_len,
            "C1: OTCreateConfiguration FAIL (listener)", 0);
        return (OSErr)kOSTLSC1_OTConfigFail;
    }

    oterr = noErr;
    {
        TEndpointInfo ep_info;
        OTMemzero(&ep_info, sizeof ep_info);
        /* Pass &ep_info so OT fills in the endpoint capabilities.
         * info.qlen is the maximum bind qlen this endpoint can
         * accept; if it's 0, OTBind with qlen >= 1 will always
         * fail with kOTBadAddressErr regardless of how clean the
         * address is. */
        listener_ep = OTOpenEndpointInContext(cfg_listener, 0, &ep_info,
                                              &oterr, g_ostls_ot_context);
        if (oterr != noErr || listener_ep == NULL) {
            OSTLS_LogLinef("C1 diag    OTOpenEndpoint failed err=%ld",
                           (long)oterr);
            c1_status(out_msg, out_msg_len,
                "C1: OTOpenEndpoint FAIL (listener)", (long)oterr);
            return (OSErr)kOSTLSC1_OTOpenEndptFail;
        }
        OSTLS_LogLinef("C1 diag    endpoint info: addr=%ld options=%ld tsdu=%ld",
                       (long)ep_info.addr,
                       (long)ep_info.options,
                       (long)ep_info.tsdu);
        OSTLS_LogLinef("C1 diag    endpoint info: etsdu=%ld connect=%ld discon=%ld",
                       (long)ep_info.etsdu,
                       (long)ep_info.connect,
                       (long)ep_info.discon);
        OSTLS_LogLinef("C1 diag    endpoint info: servtype=%ld flags=0x%lX qlen=%ld",
                       (long)ep_info.servtype,
                       (long)ep_info.flags,
                       (long)ep_info.qlen);
    }
    OTSetSynchronous(listener_ep);
    OTSetBlocking(listener_ep);

    /* ----- 2. Bind on 0.0.0.0:port with backlog 1 ----- */

    OTMemzero(&local_addr, sizeof local_addr);
    /*
     * Bind to 127.0.0.1 explicitly rather than INADDR_ANY (0).
     * Apple's OT documentation says 0 means "any local IP," but
     * some classic OT configurations require a concrete configured
     * interface address and reject 0 with kOTBadAddressErr. Loopback
     * is always present on a working IP stack, so binding to it is
     * the safest single-address test.
     *
     * 127.0.0.1 in host byte order = 0x7F000001 = 2130706433.
     * For a proxy that wants to accept connections from other Macs
     * on the LAN, swap this back to INADDR_ANY once the bind path
     * is known good.
     */
    OTInitInetAddress(&local_addr, (InetPort)port,
                      (InetHost)0x7F000001UL);

    OTMemzero(&bind_req, sizeof bind_req);
    bind_req.addr.buf    = (UInt8 *)&local_addr;
    bind_req.addr.maxlen = (OTByteCount)sizeof local_addr;
    bind_req.addr.len    = (OTByteCount)sizeof local_addr;
    bind_req.qlen        = 1L;

    /*
     * Diagnostic: log the exact bytes we're handing OT before the
     * bind call. Two consecutive -3150 (kOTBadAddressErr) failures
     * on hardware after the tilisten-vs-tcp switch made the address
     * itself the next suspect. The log line shows sizeof's plus the
     * 16-byte InetAddress layout so we can confirm fAddressType,
     * fPort and fHost are what we believe we wrote.
     */
    {
        const unsigned char *p = (const unsigned char *)&local_addr;
        OSTLS_LogLinef("C1 diag    sizeof(InetAddress)=%lu sizeof(TBind)=%lu qlen=%ld",
                       (unsigned long)sizeof local_addr,
                       (unsigned long)sizeof bind_req,
                       (long)bind_req.qlen);
        OSTLS_LogLinef("C1 diag    addr.maxlen=%ld addr.len=%ld addr.buf=%p",
                       (long)bind_req.addr.maxlen,
                       (long)bind_req.addr.len,
                       (void *)bind_req.addr.buf);
        OSTLS_LogLinef("C1 diag    addr[0-7]  %02X %02X %02X %02X %02X %02X %02X %02X",
                       (unsigned)p[0], (unsigned)p[1], (unsigned)p[2], (unsigned)p[3],
                       (unsigned)p[4], (unsigned)p[5], (unsigned)p[6], (unsigned)p[7]);
        OSTLS_LogLinef("C1 diag    addr[8-15] %02X %02X %02X %02X %02X %02X %02X %02X",
                       (unsigned)p[8],  (unsigned)p[9],  (unsigned)p[10], (unsigned)p[11],
                       (unsigned)p[12], (unsigned)p[13], (unsigned)p[14], (unsigned)p[15]);
    }

    /*
     * Provide a returned-bind buffer rather than NULL. Some classic
     * OT versions document NULL as acceptable but reject it in
     * practice for passive (qlen >= 1) binds; supplying a valid
     * sink for the actual-bound-address write costs us 24 bytes of
     * stack and removes one ambiguity from the failure modes.
     */
    {
        TBind bind_ret;
        InetAddress bound_addr;
        OTMemzero(&bind_ret, sizeof bind_ret);
        OTMemzero(&bound_addr, sizeof bound_addr);
        bind_ret.addr.buf    = (UInt8 *)&bound_addr;
        bind_ret.addr.maxlen = (OTByteCount)sizeof bound_addr;
        bind_ret.addr.len    = 0;

        oterr = OTBind(listener_ep, &bind_req, &bind_ret);
        if (oterr != noErr) {
            OSTLS_LogLinef("C1 diag    OTBind returned err=%ld", (long)oterr);
            c1_status(out_msg, out_msg_len, "C1: OTBind FAIL", (long)oterr);
            OTCloseProvider(listener_ep);
            return (OSErr)kOSTLSC1_OTBindFail;
        }
        /* Log what we actually got bound to so we can see whether OT
         * picked the port we requested or assigned a different one. */
        OSTLS_LogLinef("C1 diag    OTBind OK actual port=%u host=0x%08lX",
                       (unsigned)bound_addr.fPort,
                       (unsigned long)bound_addr.fHost);
    }

    /* ----- 3. OTListen -- blocks until a peer arrives ----- */

    OTMemzero(&peer_addr, sizeof peer_addr);
    OTMemzero(&call, sizeof call);
    call.addr.buf    = (UInt8 *)&peer_addr;
    call.addr.maxlen = (OTByteCount)sizeof peer_addr;
    call.addr.len    = 0;

    oterr = OTListen(listener_ep, &call);
    if (oterr != noErr) {
        c1_status(out_msg, out_msg_len, "C1: OTListen FAIL", (long)oterr);
        OTCloseProvider(listener_ep);
        return (OSErr)kOSTLSC1_OTListenFail;
    }

    /* ----- 4. Open child endpoint, bind it, accept ----- */

    cfg_child = OTCreateConfiguration("tcp");
    oterr = noErr;
    child_ep = OTOpenEndpointInContext(cfg_child, 0, NULL,
                                       &oterr, g_ostls_ot_context);
    if (oterr != noErr || child_ep == NULL) {
        c1_status(out_msg, out_msg_len,
            "C1: OTOpenEndpoint FAIL (child)", (long)oterr);
        OTCloseProvider(listener_ep);
        return (OSErr)kOSTLSC1_OTAcceptOpenFail;
    }
    OTSetSynchronous(child_ep);
    OTSetBlocking(child_ep);

    oterr = OTBind(child_ep, NULL, NULL);
    if (oterr != noErr) {
        c1_status(out_msg, out_msg_len,
            "C1: OTBind FAIL (child)", (long)oterr);
        OTCloseProvider(child_ep);
        OTCloseProvider(listener_ep);
        return (OSErr)kOSTLSC1_OTAcceptBindFail;
    }

    oterr = OTAccept(listener_ep, child_ep, &call);
    if (oterr != noErr) {
        c1_status(out_msg, out_msg_len, "C1: OTAccept FAIL", (long)oterr);
        OTCloseProvider(child_ep);
        OTCloseProvider(listener_ep);
        return (OSErr)kOSTLSC1_OTAcceptFail;
    }

    /* ----- 5. Drain client request into out_request ----- */

    while (received + 1 < out_request_cap) {
        long want = (long)((out_request_cap - 1) - received);
        got = OTRcv(child_ep, out_request + received, want, NULL);
        if (got < 0) {
            c1_status(out_msg, out_msg_len, "C1: OTRcv FAIL", (long)got);
            OTSndOrderlyDisconnect(child_ep);
            OTCloseProvider(child_ep);
            OTCloseProvider(listener_ep);
            return (OSErr)kOSTLSC1_OTRcvFail;
        }
        if (got == 0) {
            /* Peer closed. */
            break;
        }
        received += (size_t)got;
    }
    out_request[received] = '\0';

    if (received == 0) {
        c1_status(out_msg, out_msg_len,
            "C1: peer connected but sent no bytes", 0);
        OTSndOrderlyDisconnect(child_ep);
        OTCloseProvider(child_ep);
        OTCloseProvider(listener_ep);
        return (OSErr)kOSTLSC1_PeerClosedEmpty;
    }

    /* ----- 6. Success ----- */

    {
        unsigned int peer_h_a, peer_h_b, peer_h_c, peer_h_d;
        peer_h_a = (unsigned int)((peer_addr.fHost >> 24) & 0xFFU);
        peer_h_b = (unsigned int)((peer_addr.fHost >> 16) & 0xFFU);
        peer_h_c = (unsigned int)((peer_addr.fHost >>  8) & 0xFFU);
        peer_h_d = (unsigned int)((peer_addr.fHost      ) & 0xFFU);
        sprintf(out_msg,
            "C1 OK port=%u peer=%u.%u.%u.%u:%u bytes=%lu",
            (unsigned)port,
            peer_h_a, peer_h_b, peer_h_c, peer_h_d,
            (unsigned)peer_addr.fPort,
            (unsigned long)received);
        out_msg[out_msg_len - 1] = '\0';
    }

    OTSndOrderlyDisconnect(child_ep);
    OTCloseProvider(child_ep);
    OTCloseProvider(listener_ep);
    return (OSErr)kOSTLSC1_OK;
}
