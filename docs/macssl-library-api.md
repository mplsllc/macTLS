# macSSL library API (v1)

Stable public surface of macSSL after the Stage C pivot. Host apps
(MacSurf, future tools) link macSSL's compiled object files and call
`OSTLS_Fetch` directly. No proxy, no listener, no port choice.

## Purpose

Perform a single validated HTTPS GET on classic Mac OS 9 / PowerPC.
Returns the decrypted response bytes to the caller.

## Supported TLS path

- TLS 1.2 only (BearSSL full profile)
- Cipher suites the engine will negotiate, in order of preference:
  - `0xCCA9` TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  - `0xCCA8` TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  - `0xC02B/0xC02C` ECDHE-ECDSA AES-GCM
  - `0xC02F/0xC030` ECDHE-RSA AES-GCM
  - (others available via `br_ssl_client_init_full`)
- ChaCha20-Poly1305 is preferred over AES-GCM on PowerPC where AES
  has no hardware acceleration. Verified on G3 / OS 9.1: cipher
  suite `0xCCA9` against google.com.
- 10 embedded root CAs cover Amazon, DigiCert (G2/G3), Google (GTS
  R1/R2/R3/R4), Let's Encrypt (ISRG X1/X2), and Starfield Services
  G2. See `os9/ostls_b3_anchors.h` for the full list with expiry
  dates; rotation script at `tools/regenerate_anchors.sh`.

## Function signature

```c
#include "ostls_fetch.h"

OSErr OSTLS_Fetch(
    const char *host,           /* "google.com" or "10.42.0.145"       */
    UInt16      port,           /* 443                                  */
    const char *server_name,    /* SNI + cert hostname match            */
    const char *path,           /* "/" or "/api/v1/posts"               */
    void       *out_buf,        /* caller buffer for response bytes     */
    UInt32      out_cap,        /* size of out_buf                      */
    UInt32     *out_len,        /* actual bytes copied (optional)       */
    char       *out_msg,        /* status string (always NUL-terminated)*/
    UInt32      out_msg_len     /* size of out_msg (recommend >= 180)   */
);
```

Returns `kOSTLSFetch_OK` (0) on success or a `kOSTLSFetch_*` code
in the 1000..1019 range. `out_msg` always carries a short diagnostic
string including the underlying BearSSL or OT error code where
applicable.

## Caller responsibilities

- **Open Transport must be initialised before the first call** to
  `OSTLS_Fetch`:
  ```c
  OTClientContextPtr g_ostls_ot_context = NULL;
  InitOpenTransportInContext(kInitOTForApplicationMask,
                             &g_ostls_ot_context);
  ```
  The library expects the global `g_ostls_ot_context` to be in
  scope and valid.
- Close OT at shutdown:
  ```c
  CloseOpenTransportInContext(g_ostls_ot_context);
  ```
- The caller allocates `out_buf` and `out_msg`. The library never
  allocates on the caller's behalf and does not own the buffers.
- The caller must not invoke `OSTLS_Fetch` reentrantly from inside
  another `OSTLS_Fetch` (v1 uses static BearSSL contexts).

## Memory ownership

| Pointer | Owner | Lifetime |
|---|---|---|
| `host` / `server_name` / `path` | caller | only needs to be valid during the call |
| `out_buf` | caller | must be valid during the call; library writes ≤ out_cap bytes |
| `out_msg` | caller | must be valid during the call; library writes a NUL-terminated string ≤ out_msg_len |
| `out_len` (if non-NULL) | caller | written before return |

BearSSL contexts (`br_ssl_client_context`, `br_x509_minimal_context`)
and the bidirectional I/O buffer (`BR_SSL_BUFSIZE_BIDI` = 33 178 bytes)
live in macSSL's BSS — caller doesn't see them. Per-fetch resident
memory total is ~50 KB, comfortable within MacSurf's 16 MB Carbon
partition.

## Blocking behaviour

- **Synchronous and blocking.** The call returns when the entire
  handshake + HTTP exchange completes, fails, or hits the 60-second
  deadline.
- The host app's `WaitNextEvent` loop will not be serviced during
  the call. For a UI app this manifests as a frozen window during
  the fetch.
- v2 will add an async / callback-based variant for use from inside
  a cooperative event loop. v1 is deliberately synchronous to keep
  the first ship narrow.

## Error code ranges

```
1000  kOSTLSFetch_BadArgs           — NULL pointer, zero port, etc.
1001  kOSTLSFetch_ClockBefore2000   — Mac clock unset / PRAM battery dead
1002  kOSTLSFetch_OTConfigFail      — OTCreateConfiguration("tcp") failed
1003  kOSTLSFetch_OTOpenEndptFail   — OTOpenEndpointInContext failed
1004  kOSTLSFetch_OTBindFail        — OTBind (NULL,NULL) outbound failed
1005  kOSTLSFetch_OTDnsAddrFail     — OTInitDNSAddress failed
1006  kOSTLSFetch_OTConnectFail     — TCP connect to host:port failed
1007  kOSTLSFetch_EntropyFail       — entropy injection rejected
1008  kOSTLSFetch_ClientResetFail   — br_ssl_client_reset returned 0
1009  kOSTLSFetch_OTSndFail         — OTSnd error mid-transfer
1010  kOSTLSFetch_OTRcvFail         — OTRcv error mid-transfer
1011  kOSTLSFetch_HandshakeTimeout  — 60s deadline expired
1012  kOSTLSFetch_BearSSLError      — handshake or record-layer failure
                                       (BR_ERR_X509_*, BR_ERR_SSL_*,
                                       etc. in out_msg)
1013  kOSTLSFetch_RequestTooBig     — GET line doesn't fit in sendapp buf
1014  kOSTLSFetch_NoBytesReceived   — peer closed before any plaintext
```

The Stage A-B probe codes (100..619) are intentionally distinct so
caller-side switch statements can mix library and harness codes
without collision.

## Current limitations (v1)

```
synchronous / blocking fetch
single request per call
HTTP/1.0 + Connection: close only
no streaming callback yet (entire response must fit in out_buf)
no POST / PUT / DELETE yet
no redirect following yet
no chunked transfer-encoding decoder
fixed embedded trust anchor set (10 roots; see ostls_b3_anchors.h)
no root-store UI (anchors are baked in at build time)
entropy is the Stage A insecure stub — replace before production HTTPS
no session resumption — every call does a full handshake
```

The entropy gap is the biggest of these. The Stage A entropy mixes
TickCount, Microseconds, stack address, and a fixed tag into a
32-byte buffer just enough to satisfy BearSSL's entropy gate. **It
is NOT cryptographically sound.** Replacing it with a production
entropy gathering (mouse delta, key latency jitter, OT notifier
tick jitter, persisted seed file) is the prerequisite for shipping
HTTPS to end users as a security claim, separate from the
networking work.

## Example usage

```c
#include <OpenTransport.h>
#include "ostls_fetch.h"

OTClientContextPtr g_ostls_ot_context = NULL;

int main(void)
{
    OSErr err;
    UInt32 len = 0;
    unsigned char response[256];
    char msg[180];

    InitOpenTransportInContext(kInitOTForApplicationMask,
                               &g_ostls_ot_context);

    err = OSTLS_Fetch(
        "google.com",       /* host        */
        443,                /* port        */
        "google.com",       /* server_name */
        "/",                /* path        */
        response, sizeof response,
        &len,
        msg, sizeof msg);

    if (err == kOSTLSFetch_OK) {
        /* response[] holds 'len' bytes of decrypted HTTP, e.g.
         *   "HTTP/1.0 301 Moved Permanently\r\nLocation: ...\r\n"
         */
    } else {
        /* msg holds a diagnostic string */
    }

    CloseOpenTransportInContext(g_ostls_ot_context);
    return 0;
}
```

For the integration path into MacSurf specifically, see
[macssl-integration-notes.md](macssl-integration-notes.md).

## v2 roadmap (not yet shipped)

- Async / callback variant: `OSTLS_FetchAsync(...)` that returns
  immediately and invokes a caller callback at completion. Lets
  the host app keep its event loop alive.
- Socket-like API: `OSTLS_Open(host, port, sni)` →
  `OSTLS_Write(conn, ...)` / `OSTLS_Read(conn, ...)` → `OSTLS_Close(conn)`.
  Multiple in-flight connections; streaming.
- Production entropy gathering (independent of API surface).
- Redirect handling + chunked transfer-encoding decoder built into
  the library.
- POST / PUT request body support.
