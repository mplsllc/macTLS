# macSSL

macSSL brings native HTTPS to classic Mac OS 9. It's a small C
library that opens a TLS 1.2 connection from a PowerPC Mac
application, validates the certificate chain against ten embedded
root CAs, and returns the decrypted response bytes. Compiled under
CodeWarrior 8 Pro; verified end-to-end on a real Power Macintosh G3
running Mac OS 9.1.

The cipher suite that gets negotiated on a typical fetch is
`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` — modern, forward-secret,
and the right choice for a CPU without AES hardware acceleration. It
works against Google. It works against any modern HTTPS endpoint
whose chain terminates in one of the embedded roots (Amazon, DigiCert,
Google Trust Services, Let's Encrypt, Starfield).

The whole API:

```c
OSErr OSTLS_Fetch(
    const char *host,           /* "google.com"                       */
    UInt16      port,           /* 443                                */
    const char *server_name,    /* SNI + cert-hostname match          */
    const char *path,           /* "/" or "/api/v1/whatever"          */
    void       *out_buf,        /* caller buffer for response bytes   */
    UInt32      out_cap,        /* size of out_buf                    */
    UInt32     *out_len,        /* actual bytes copied (optional)     */
    char       *out_msg,        /* status string                      */
    UInt32      out_msg_len);
```

One function. Statically link macSSL into your app and call it.
MacSurf is the first downstream consumer; nothing about the API is
MacSurf-specific.

The original shape *was* a local proxy on `127.0.0.1:8765` that any
classic browser would point at as its HTTP proxy. Carbon CFM has an
undocumented quirk that makes that impossible:
`OTOpenEndpointInContext` endpoints cannot bind to a caller-chosen
address. Fourteen rounds of probing established this conclusively;
the full investigation is at
[`docs/carbon-ot-passive-bind-finding.md`](docs/carbon-ot-passive-bind-finding.md).
The library shape works around the platform limit and is arguably the
better architecture anyway — single function call, no daemon to
manage, no port to configure.

## What's in v0.1 and v0.2

```
v0.1 -- blocking API
  TLS 1.2 validated handshake                working -- verified G3 / OS 9.1
  ECDHE-ECDSA + ChaCha20-Poly1305            working (suite 0xCCA9)
  ECDHE-RSA + AES-GCM (alternate suites)     working
  X.509 chain validation                     working -- 10 embedded root CAs
  OS 9 system clock -> BearSSL date          working -- proleptic Gregorian
  HTTPS GET via OSTLS_Fetch                  working -- returns decrypted body

v0.2 -- non-blocking TLS stream API (shipped, hardware-verification pending)
  OSTLS_New / Start / Pump / Read / Write    socket-like async surface
  Bounded Pump (max_steps)                   never blocks; host UI stays responsive
  Internal 4 KB read ring + 4 KB write queue back-pressure on caller-side stalls
  Async OT via OTAsyncOpenEndpointInContext  notifier-driven event dispatch
  OSTLS_Close / Dispose lifecycle            edge cases including Dispose-without-Close
  Stage D1 async OT smoke probe              permanent regression for the OT plumbing
  Stage D2 async TLS regression              full handshake + Write + chunked Read
```

The verified Stage D run log against `google.com:443` is archived
at [`docs/runs/2026-05-19-b4-google-ok.txt`](docs/runs/2026-05-19-b4-google-ok.txt) —
useful as a regression reference.

## Roadmap

In rough priority order:

**v0.2 hardware verification.** The async TLS stream API is
implemented (see `os9/ostls_async.{h,c}` and Stage D1 + D2 in
MacSSLTest) but hasn't been exercised on real hardware yet. Until
both Stage D (blocking baseline) and Stage D2 (async via
OSTLSConnection) come back green on a G3, v0.2 is "code complete,
not validated."

**v0.3 — HTTP convenience layer.** Redirect following, chunked
transfer-encoding decoder, HTTP POST, session resumption. These
are feature gaps; landing them gives MacSurf-side integration a
much cleaner path to handle real sites.

**v1.0 — production entropy.** macSSL's current PRNG seed
([`os9/ostls_entropy.c`](os9/ostls_entropy.c)) mixes a `TickCount`,
a `Microseconds` reading, a stack address, and a fixed tag into a
32-byte buffer. It satisfies BearSSL's seeded-check but it isn't
the strong-randomness gathering a TLS implementation deserves. The
plan for replacing it — mouse-delta gathering across an idle
window, key latency jitter, OT notifier tick jitter, and a
persisted seed file rolled at clean shutdown — is documented at
[`docs/macssl-integration-notes.md`](docs/macssl-integration-notes.md)
section 3. v1.0 unlocks the "security claim is real" story.

**MacSurf integration.** Land a `macos9_https_fetcher.c` in the
MacSurf frontend that calls into macSSL via the async API. Held
until v0.2 is hardware-verified and v0.3 streaming makes the
fetcher state machine cleaner. Design notes:
[`docs/macssl-integration-notes.md`](docs/macssl-integration-notes.md).

## How it's wired

```
your app          OSTLS_Fetch(...)
  │
  ▼
macSSL            (this repo, ~5 KB of glue)
  │
  ├─► BearSSL     vendored at 7bea48e5; ~250 .c files, MIT.
  │                 i31 bigint, X25519, ChaCha20-Poly1305,
  │                 SHA-256, X.509 minimal validator.
  │
  ▼
Open Transport    OTConnect, OTSnd, OTRcv
  │
  ▼
remote HTTPS server
```

Per-fetch resident memory is around 50 KB — one `br_ssl_client_context`,
one `br_x509_minimal_context`, and a 33 KB bidirectional I/O buffer.
That fits inside a Carbon CFM app's 16 MB partition with room to
spare.

`OSTLS_Fetch` is synchronous: it returns when the handshake
completes, the GET goes out, the response is captured up to the
buffer size, and the peer closes. A non-blocking variant is on the
roadmap above; for v0.1 the host's UI freezes during the call. On
a typical fetch that's a few seconds.

## Repo layout

```
os9/                          OS 9 integration, in the build target
  ostls_fetch.{h,c}             public API
  ostls_b3_anchors.{h,c}        10 embedded trust anchors
  ostls_b3_handshake.{h,c}      validated handshake (internal)
  ostls_b1_tcp.{h,c}            raw OT TCP connect (diagnostic stage)
  ostls_b2_handshake.{h,c}      insecure-validator handshake (diagnostic)
  ostls_smoketest.{h,c}         BearSSL init smoke (diagnostic)
  ostls_mul64_probe.{h,c}       PPC codegen probe (diagnostic)
  ostls_entropy.{h,c}           PRNG seed (Stage A stub — see roadmap)
  ostls_time.{h,c}              OS 9 clock → BearSSL date conversion
  ostls_log.{h,c}               file-backed log channel
  ostls_cw8_prefix.h            CW8 language workarounds
  ssl_engine_cw8.c              C89-patched copy of BearSSL's ssl_engine.c
  archive/                      historical references — NOT in build

bearssl/                      vendored upstream (commit 7bea48e5)
MacSSLTest/                   Carbon CFM regression harness
docs/                         design notes, run logs, investigation reports
tools/regenerate_anchors.sh   refresh trust-anchor source from PEMs
```

## Building

CodeWarrior 8 Pro on real Mac OS 9. Add `bearssl/src/**/*.c`
(skipping `bearssl/src/ssl/ssl_engine.c`, which
`os9/ssl_engine_cw8.c` replaces), all of `os9/ostls_*.c`,
`os9/ssl_engine_cw8.c`, and `MacSSLTest/main.c` to a Carbon CFM PPC
project. Project prefix:
`MacSSLTest/macssltest_prefix.h`. Access paths: every
`bearssl/src/` subdirectory (CW8 doesn't recurse), plus
`bearssl/inc/`, `os9/`, `MacSSLTest/`. Libraries:
`MSL_C_Carbon.Lib`, `MSL_Runtime_PPC.Lib`, `MathLib`, `CarbonLib`.
Partition size: 16 MB preferred / 8 MB minimum.

For Linux-side syntax checking during development, use
[Retro68](https://github.com/autc04/Retro68) GCC with `-std=c89
-pedantic-errors`. The exact invocation lives in
[`tools/regenerate_anchors.sh`](tools/regenerate_anchors.sh) and the
[memory file](docs/macssl-integration-notes.md) for the project.

## Other classic-Mac TLS work

macSSL didn't come out of nowhere. A few other projects are doing
related work:

- [**Certainly**](https://github.com/minorbug/certainly) (minorbug):
  BearSSL + Open Transport, Retro68 toolchain, TLS 1.3. Closest
  sibling — different toolchain (Retro68 vs CodeWarrior 8) and
  different API style (pump-loop vs single-call) but the same
  crypto substrate. macSSL's 10-anchor trust set matches Certainly's.

- [**MacSSL** (bbenchoff)](https://github.com/bbenchoff/MacSSL):
  Brian Benchoff's mbedtls/PolarSSL port to CodeWarrior Pro 4 for
  classic Mac OS 7/8/9. First public demonstration that the
  CodeWarrior + classic Mac + TLS path works at all. Frozen since
  2024; TLS 1.1, single hardcoded site. The naming collision is a
  coincidence — separate projects.

- [**Crypto Ancienne**](https://github.com/classilla/cryanc) /
  `carl` (Cameron Kaiser): TLSe-based proxy tool that runs under
  MPW. Known to work with Classilla 9.3.4b. Different runtime
  model — MPW shell tool, not a Carbon library — but it validates
  that old browsers can drive a local HTTPS-fetching helper if
  there's one to be driven.

Full landscape including projects that aren't worth chasing for
this niche is at the bottom of
[`docs/macssl-integration-notes.md`](docs/macssl-integration-notes.md).

## Tags

- **v0.1.0** (2026-05-19) — first version with a working
  `OSTLS_Fetch`. Blocking API; verified on G3 / OS 9.1.
- **v0.2.0** (in progress) — non-blocking async TLS stream API
  (`OSTLS_New / Start / Pump / Write / Read / Close / Dispose`).
  Code complete; tag bump waits on hardware verification of
  Stage D2.

## License

MIT, see [LICENSE](LICENSE). BearSSL is also MIT and is vendored
under `bearssl/` with its own license file. No other third-party
code is statically linked into the build.
