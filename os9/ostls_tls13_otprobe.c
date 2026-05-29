/*
 * ostls_tls13_otprobe.c -- TLS 1.3 handshake over Open Transport.
 *
 * OT setup mirrors B2 (OTOpenEndpointInContext, sync + blocking, OTBind,
 * OTInitDNSAddress, OTConnect). The handshake itself is driven exactly
 * like the host harness: call tls13_handshake_step, flush msg_buf with
 * OTSnd, pull bytes with OTRcv on WantRead, finish when the state reaches
 * kTLS13_Complete. The chain is validated against the embedded anchors
 * (br_ssl_client_init_full + br_x509_minimal), so this is the real,
 * validated 1.3 handshake -- just over OT.
 */

#include "ostls_tls13_otprobe.h"
#include "ostls_tls13_handshake.h"
#include "ostls_entropy.h"
#include "ostls_time.h"
#include "ostls_b3_anchors.h"
#include "ostls_log.h"

#include "bearssl_ssl.h"
#include "bearssl_x509.h"

#include <stdio.h>
#include <string.h>

#ifdef __MWERKS__
#include <Types.h>
#include <Events.h>             /* TickCount */
#include <Files.h>
#include <OpenTransport.h>
#include <OpenTptInternet.h>
extern OTClientContextPtr g_ostls_ot_context;
#else
/* Non-CW8 syntax-check stubs (mirror B2). Not executed under Retro68. */
typedef long OSStatus;
typedef long OTResult;
typedef void *EndpointRef;
typedef void *OTConfigurationRef;
typedef short OTByteCount;
typedef unsigned char UInt8;
typedef struct { OTByteCount maxlen, len; UInt8 *buf; } TNetbuf;
typedef struct { TNetbuf addr, opt, udata; long sequence; } TCall;
typedef struct { unsigned short fAddressType; char fName[1]; } DNSAddress;
#ifndef noErr
#define noErr 0
#endif
#define kOTNoDataErr -3162
static unsigned long TickCount(void) { return 0; }
static OTConfigurationRef OTCreateConfiguration(const char *s){(void)s;return (OTConfigurationRef)1;}
static EndpointRef OTOpenEndpointInContext(OTConfigurationRef c,unsigned long f,void *p,OSStatus *e,void *x){(void)c;(void)f;(void)p;(void)x;*e=noErr;return (EndpointRef)1;}
static OSStatus OTSetSynchronous(EndpointRef e){(void)e;return noErr;}
static OSStatus OTSetNonBlocking(EndpointRef e){(void)e;return noErr;}
static OSStatus OTBind(EndpointRef e,void *a,void *b){(void)e;(void)a;(void)b;return noErr;}
static OSStatus OTConnect(EndpointRef e,TCall *c,void *r){(void)e;(void)c;(void)r;return noErr;}
static OTResult OTSnd(EndpointRef e,void *b,long n,long f){(void)e;(void)b;(void)f;return n;}
static OTResult OTRcv(EndpointRef e,void *b,long n,long *f){(void)e;(void)b;(void)f;return n;}
static OSStatus OTSndOrderlyDisconnect(EndpointRef e){(void)e;return noErr;}
static OSStatus OTCloseProvider(EndpointRef e){(void)e;return noErr;}
static long OTInitDNSAddress(DNSAddress *d,const char *s){(void)d;(void)s;return 0;}
static void OTMemzero(void *p,unsigned long n){memset(p,0,n);}
extern void *g_ostls_ot_context;
#endif

/* Static contexts -- the handshake ctx and recv buffer are large; keep
 * them off the OS 9 stack. */
static br_ssl_client_context  gT13Client;
static br_x509_minimal_context gT13X509;
static unsigned char           gT13IoBuf[BR_SSL_BUFSIZE_BIDI];
static tls13_hs_ctx            gT13Hs;
static unsigned char           gT13Recv[32768];
static unsigned char           gT13Wire[640];
/* Decrypted app-data plaintext goes into gT13IoBuf: it's the BearSSL
 * engine record buffer (BR_SSL_BUFSIZE_BIDI, ~33 KB), but the 1.3 path
 * never drives the engine's record I/O, so it's free after handshake
 * setup. Reusing it avoids a separate 16 KB static that would tighten
 * the MacTLSTest heap (the async Stage D2 NewPtr is sensitive to it). */
#define gT13Plain gT13IoBuf

static void ot13_status(char *out, unsigned long cap, const char *msg, long code)
{
    if (out == NULL || cap == 0) return;
    if (code != 0) {
        sprintf(out, "%.100s (%ld)", msg, code);
    } else {
        sprintf(out, "%.120s", msg);
    }
}

/*
 * After the handshake, send an HTTP GET over the 1.3 record layer and
 * read the response. The server may send NewSessionTicket records first
 * (inner content type handshake); we decrypt every record to keep the
 * read sequence aligned, skip the tickets, and capture the first
 * application_data record (the HTTP response status line). Returns noErr
 * on getting a response. rbuf/rlen hold any leftover handshake bytes.
 */
static OSErr ot13_appdata(EndpointRef ep, const char *server_name,
                          unsigned char *rbuf, size_t rlen, size_t cap,
                          char *out_msg, unsigned long out_msg_len)
{
    char get[256];
    unsigned char ct[512];
    size_t getlen, clen, plen;
    uint8_t inner;
    unsigned long deadline;

    /* Build a minimal HTTP/1.1 GET. */
    sprintf(get, "GET / HTTP/1.1\r\nHost: %.180s\r\nConnection: close\r\n\r\n",
            server_name);
    getlen = strlen(get);

    clen = 0;
    if (tls13_record_encrypt(&gT13Hs.write_ctx, get, getlen,
                             TLS13_CT_APPLICATION_DATA, ct, &clen) != 0) {
        ot13_status(out_msg, out_msg_len, "T13: app-data encrypt FAIL", 0);
        return (OSErr)20;
    }
    gT13Wire[0] = 0x17; gT13Wire[1] = 0x03; gT13Wire[2] = 0x03;
    gT13Wire[3] = (unsigned char)(clen >> 8);
    gT13Wire[4] = (unsigned char)clen;
    memcpy(gT13Wire + 5, ct, clen);

    {
        OTResult sent;
        unsigned long off = 0;
        while (off < 5 + clen) {
            sent = OTSnd(ep, gT13Wire + off, (long)((5 + clen) - off), 0);
            if (sent < 0) {
                ot13_status(out_msg, out_msg_len, "T13: app-data OTSnd FAIL",
                            (long)sent);
                return (OSErr)21;
            }
            off += (unsigned long)sent;
        }
    }

    deadline = TickCount() + (unsigned long)(30UL * 60UL);  /* 30s */
    for (;;) {
        while (rlen >= 5) {
            size_t reclen = ((size_t)rbuf[3] << 8) | (size_t)rbuf[4];
            int dr;
            if (rlen < 5 + reclen) break;
            plen = 0; inner = 0;
            dr = tls13_record_decrypt(&gT13Hs.read_ctx, rbuf + 5, reclen,
                                      gT13Plain, &plen, &inner);
            memmove(rbuf, rbuf + 5 + reclen, rlen - (5 + reclen));
            rlen -= (5 + reclen);
            if (dr != 0) {
                ot13_status(out_msg, out_msg_len, "T13: app-data decrypt FAIL", 0);
                return (OSErr)22;
            }
            if (inner == TLS13_CT_APPLICATION_DATA) {
                unsigned long n = (plen < 90UL) ? (unsigned long)plen : 90UL;
                unsigned long i;
                char snip[96];
                for (i = 0; i < n; i++) {
                    char c = (char)gT13Plain[i];
                    snip[i] = (c == '\r' || c == '\n') ? ' ' : c;
                }
                snip[n] = '\0';
                if (out_msg != NULL && out_msg_len > 0) {
                    sprintf(out_msg, "T13: 1.3 HTTP OK: %.90s", snip);
                }
                return noErr;
            } else if (inner == TLS13_CT_ALERT) {
                ot13_status(out_msg, out_msg_len, "T13: app-data server ALERT",
                            (long)((plen > 1) ? gT13Plain[1] : -1));
                return (OSErr)23;
            }
            /* else handshake (NewSessionTicket / KeyUpdate): skip. */
        }
        if (TickCount() > deadline) {
            ot13_status(out_msg, out_msg_len, "T13: app-data timeout", 0);
            return (OSErr)24;
        }
        {
            OTResult got = OTRcv(ep, rbuf + rlen, (long)(cap - rlen), NULL);
            if (got > 0) {
                rlen += (size_t)got;
            } else if (got == kOTNoDataErr) {
                /* poll again (deadline-bounded) */
            } else {
                ot13_status(out_msg, out_msg_len, "T13: app-data OTRcv FAIL",
                            (long)got);
                return (OSErr)25;
            }
        }
    }
}

OSErr OSTLS_TLS13_OTProbe(const char *target_host_port,
                          const char *server_name,
                          char *out_msg, unsigned long out_msg_len,
                          unsigned short *out_cipher)
{
    OTConfigurationRef cfg;
    EndpointRef ep;
    OSStatus oterr;
    TCall call;
    DNSAddress dns;
    long dns_len;
    const br_x509_trust_anchor *tas;
    size_t tas_n;
    UInt32 br_days, br_secs;
    OSErr time_err;
    int entropy_err;
    size_t recv_len;
    unsigned long deadline;
    int done, ok;
    int last_state;

    if (out_cipher != NULL) *out_cipher = 0;

    /* ----- 1. OT endpoint setup (mirror B2) ----- */
    cfg = OTCreateConfiguration("tcp");
    if (cfg == NULL || cfg == (OTConfigurationRef)-1L) {
        ot13_status(out_msg, out_msg_len, "T13: OTCreateConfiguration FAIL", 0);
        return (OSErr)1;
    }
    oterr = noErr;
    ep = OTOpenEndpointInContext(cfg, 0, NULL, &oterr, g_ostls_ot_context);
    if (oterr != noErr || ep == NULL) {
        ot13_status(out_msg, out_msg_len, "T13: OTOpenEndpoint FAIL", (long)oterr);
        return (OSErr)2;
    }
    OTSetSynchronous(ep);
    /* Non-blocking: OTRcv returns whatever bytes are available (or
     * kOTNoDataErr if none) rather than blocking trying to fill our big
     * buffer. The drive loop polls and lets the step consume complete
     * records as they arrive. Blocking + a large buffer made OTRcv stall
     * ~60s waiting to fill before returning the (complete) ServerHello. */
    OTSetNonBlocking(ep);

    oterr = OTBind(ep, NULL, NULL);
    if (oterr != noErr) {
        ot13_status(out_msg, out_msg_len, "T13: OTBind FAIL", (long)oterr);
        OTCloseProvider(ep);
        return (OSErr)3;
    }

    OTMemzero(&call, sizeof(call));
    dns_len = OTInitDNSAddress(&dns, (char *)target_host_port);
    if (dns_len <= 0) {
        ot13_status(out_msg, out_msg_len, "T13: OTInitDNSAddress FAIL", dns_len);
        OTCloseProvider(ep);
        return (OSErr)4;
    }
    call.addr.buf = (UInt8 *)&dns;
    call.addr.len = (short)dns_len;

    oterr = OTConnect(ep, &call, NULL);
    if (oterr != noErr) {
        ot13_status(out_msg, out_msg_len, "T13: OTConnect FAIL", (long)oterr);
        OTCloseProvider(ep);
        return (OSErr)5;
    }

    /* ----- 2. BearSSL engine + validated X.509 + handshake setup ----- */
    OSTLS_B3_GetAnchors(&tas, &tas_n);
    br_ssl_client_init_full(&gT13Client, &gT13X509, tas, tas_n);
    br_ssl_engine_set_buffer(&gT13Client.eng, gT13IoBuf, sizeof gT13IoBuf, 1);

    time_err = OSTLS_GetBearSSLTime(&br_days, &br_secs);
    if (time_err != kOSTLSTimeOK) {
        ot13_status(out_msg, out_msg_len, "T13: system clock before 2000", 0);
        OTSndOrderlyDisconnect(ep);
        OTCloseProvider(ep);
        return (OSErr)6;
    }
    br_x509_minimal_set_time(&gT13X509, br_days, br_secs);

    entropy_err = OSTLS_InjectEntropy(&gT13Client.eng);
    if (entropy_err != 0) {
        ot13_status(out_msg, out_msg_len, "T13: entropy inject FAIL", 0);
        OTSndOrderlyDisconnect(ep);
        OTCloseProvider(ep);
        return (OSErr)7;
    }

    tls13_handshake_init(&gT13Hs);
    gT13Hs.x509_ctx = (const br_x509_class **)&gT13X509.vtable;
    gT13Hs.eng = &gT13Client.eng;

    /* ----- 3. Drive the handshake over OT ----- */
    recv_len = 0;
    done = 0;
    ok = 0;
    last_state = -1;
    deadline = TickCount() + (unsigned long)(60UL * 60UL);  /* 60s */

    while (!done) {
        tls13_hs_result r;

        if (TickCount() > deadline) {
            ot13_status(out_msg, out_msg_len, "T13: handshake timeout (60s)", 0);
            break;
        }

        r = tls13_handshake_step(&gT13Hs, gT13Recv, &recv_len, server_name);

        /* Log only on state change, so the no-data poll doesn't spam. */
        if ((int)gT13Hs.state != last_state) {
            OSTLS_LogLinef("  T13 state->%d (r=%d msglen=%lu rlen=%lu)",
                           (int)gT13Hs.state, (int)r,
                           (unsigned long)gT13Hs.msg_len,
                           (unsigned long)recv_len);
            last_state = (int)gT13Hs.state;
        }

        /* Flush any outgoing message fully before advancing. */
        while (gT13Hs.msg_offset < gT13Hs.msg_len) {
            OTResult sent = OTSnd(ep, gT13Hs.msg_buf + gT13Hs.msg_offset,
                                  (long)(gT13Hs.msg_len - gT13Hs.msg_offset), 0);
            if (sent < 0) {
                ot13_status(out_msg, out_msg_len, "T13: OTSnd FAIL", (long)sent);
                done = 1;
                break;
            }
            OSTLS_LogLinef("  T13 OTSnd sent=%ld", (long)sent);
            gT13Hs.msg_offset += (size_t)sent;
        }
        if (done) break;

        /* Completion is by STATE, not result code. */
        if (gT13Hs.state == kTLS13_Complete &&
            gT13Hs.msg_offset >= gT13Hs.msg_len) {
            ok = 1;
            done = 1;
            break;
        }

        if (r == kTLS13_Error) {
            ot13_status(out_msg, out_msg_len, "T13: handshake Error br_err",
                        (long)gT13Hs.error);
            break;
        } else if (r == kTLS13_Fallback12) {
            ot13_status(out_msg, out_msg_len, "T13: server chose TLS 1.2", 0);
            break;
        } else if (r == kTLS13_WantRead) {
            OTResult got = OTRcv(ep, gT13Recv + recv_len,
                                 (long)(sizeof(gT13Recv) - recv_len), NULL);
            if (got > 0) {
                OSTLS_LogLinef("  T13 OTRcv got=%ld (rlen now %lu)",
                               (long)got,
                               (unsigned long)(recv_len + (size_t)got));
                recv_len += (size_t)got;
            } else if (got == kOTNoDataErr) {
                /* no data yet -- poll again (deadline-bounded) */
            } else {
                ot13_status(out_msg, out_msg_len, "T13: OTRcv FAIL/closed",
                            (long)got);
                break;
            }
        }
        /* WantWrite / OK: already flushed; loop. */
    }

    if (ok) {
        OSErr ad_err;
        if (out_cipher != NULL) *out_cipher = gT13Hs.cipher_suite;
        /* Drive a real HTTP request/response over the 1.3 record layer.
         * This is what actually exercises the client application keys --
         * the handshake alone completes even with a broken app-key
         * derivation, so app-data is the real end-to-end proof. */
        ad_err = ot13_appdata(ep, server_name, gT13Recv, recv_len,
                              sizeof(gT13Recv), out_msg, out_msg_len);
        OTSndOrderlyDisconnect(ep);
        OTCloseProvider(ep);
        return ad_err;
    }

    OTSndOrderlyDisconnect(ep);
    OTCloseProvider(ep);
    return (OSErr)8;
}
