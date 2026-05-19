# macSSL

Native TLS for Mac OS 9, built on **BearSSL**, shipping as a standalone
**local HTTP proxy Carbon app** that any OS 9 browser can configure as
its HTTP proxy. The proxy strips TLS on behalf of clients: it accepts
plain HTTP, fetches the upstream over HTTPS via BearSSL + Open
Transport, and returns plain HTTP to the caller.

This is a **system-wide service**, not a library that any specific
browser is forced to link. Classilla, iCab, MacSurf, and anything else
that honours HTTP proxy configuration gets HTTPS for free.

## Is this safe?

**No.** This is a hobby and research project. macSSL has not been
audited by a security expert and there is no expectation that it
should be trusted with anything sensitive. The author and contributors
make no warranty of correctness, security, or fitness for any
purpose; see [LICENSE](LICENSE) for the full MIT disclaimer.

Mac OS 9 itself predates almost every modern OS-level security
mechanism — no enforced memory protection between apps, no ASLR, no
privilege separation, a network stack from a different threat era.
Even when the TLS layer works correctly the host platform is soft in
ways no one has fully catalogued. Don't use macSSL for anything
you'd regret losing. The right framing is "now my hobbyist OS 9
browser can render modern HTTPS pages," not "now my OS 9 machine is
ready for online banking."

In particular, the Stage A entropy source is **intentionally
insecure** (a few weak Toolbox time/jitter sources packed into 32
bytes — just enough to satisfy BearSSL's entropy gate). Replacing it
with proper mouse-delta / key-jitter / OT-notifier-tick / persisted-
seed gathering is required before any user-facing HTTPS shipping. See
[docs/macssl-integration-notes.md](docs/macssl-integration-notes.md)
§3 for the plan.

## Prior art

There is a small but real ecosystem of TLS-on-classic-Mac projects.
None of them target the exact niche macSSL is filling — **a native
Carbon / Open Transport local HTTPS-fetching proxy for arbitrary OS 9
browsers** — but each is useful as reference material for one or two
specific design questions. Quick map:

| Project | Crypto lib | Toolchain | Target | Shape | Why it matters here |
|---|---|---|---|---|---|
| [**Certainly**](https://github.com/minorbug/certainly) (minorbug) | BearSSL | Retro68 GCC 12, C99 | OS 9 PPC | static library, pump-loop API | Closest sibling: TLS 1.3 + 1.2 on OS 9; the async-OT pattern macSSL will adopt at Stage C |
| [**MacSSL** (bbenchoff)](https://github.com/bbenchoff/MacSSL) | mbedtls/PolarSSL 2.x | CodeWarrior Pro 4 | OS 7/8/9 (68K+PPC FAT) | one-site Toolbox app | First public CW + Classic Mac TLS demo; C89-porting tax catalogue |
| [**Crypto Ancienne / cryanc / carl**](https://github.com/classilla/cryanc) (Cameron Kaiser et al.) | TLSe | various pre-C99 compilers, MPW MrC for Classic Mac | many old systems incl. Classic Mac | command-line tool + HTTP/HTTPS proxy mode | The proxy-for-old-browsers idea; known-working with Classilla |
| [**antscode/mbedtls-Mac-68k**](https://github.com/antscode/mbedtls-Mac-68k) | mbedtls | Retro68 | 68K Macs | static lib | TLS 1.2 perf expectations on slower hardware; mbedtls config trim |
| [**antscode/MacHTTP**](https://github.com/antscode/MacHTTP) | (uses above) | Retro68, C++ | 68K Macs | HTTP/HTTPS client wrapper | Request/response API shape on top of TLS |
| [**TLSe**](https://github.com/eduardsui/tlse) (Eduard Suica) | libtomcrypt | host | not Mac-specific | single-C-file TLS 1.0/1.1/1.2/1.3 | Engine behind Crypto Ancienne — useful for comparison, not for use |

### The three that actually inform macSSL's design

**1. [Certainly](https://github.com/minorbug/certainly)** is the
closest sibling. BearSSL + Open Transport, baked-in trust anchors,
non-blocking pump-loop public API for the cooperative Toolbox event
model, TLS 1.3 + 1.2. Built with Retro68/GCC/C99. macSSL diverges
deliberately on two axes:

- **Toolchain.** macSSL uses **CW8 + C89** because the primary
  downstream consumer is MacSurf, which is itself a CW8 project;
  sharing a toolchain keeps integration painless. Certainly's
  Retro68 path is a clean alternative for projects that don't need
  CW8 compatibility.
- **Shape.** macSSL ships as a **standalone Carbon proxy app** that
  any OS 9 browser configures as its HTTP proxy. Certainly is a
  library that an app links against. Different audiences; can
  coexist on the same machine.

Specific design notes worth stealing later: `ot_transport.c`'s
notifier-sets-flags / pump-reads-flags split, the `MacTLS_Pump` API
contract, `tools/generate_ca_roots.sh` (already adopted — our 10
embedded roots match Certainly's set), the host-side test-vector
harness for TLS 1.3 key schedule (`tests/host/`), the
`examples/postman` Toolbox UI as a reference for a full HTTPS
request builder.

**2. [bbenchoff/MacSSL](https://github.com/bbenchoff/MacSSL)** is the
historical "it's possible" demo: C89/C90 port of mbedtls/PolarSSL 2.x
under CodeWarrior Pro 4, FAT (68K + PPC) Toolbox app fetching one
hardcoded endpoint over TLS 1.1, RSA-AES-CBC, SHA-1, ISRG X1 + Let's
Encrypt R11 chain. README explicitly marks the repo as a frozen
proof-of-concept.

Naming is independent — bbenchoff's "MacSSL" (capital M, GitHub since
2024) and this "macSSL" (lowercase m) were named without coordination.
They are different projects.

Useful as cold reference for: validating the path is walkable, and
documenting the C89 porting tax for a non-C89-clean crypto library
(variadic macros, hand-emulated 64-bit ints via
`struct { uint32_t high, low; }`, every operation rewritten). macSSL
sidesteps the tax entirely by using BearSSL, which is C89-clean as
shipped. Not useful for code lifting: different crypto library, TLS
1.1 only (modern endpoints frequently reject), one site, frozen
repo, and the actual app wrapper / OT glue / entropy mix described
in the README aren't in the published source tree — they're only in
the bundled `Archive.sit`.

**3. [Crypto Ancienne / cryanc / carl](https://github.com/classilla/cryanc)**
by Cameron Kaiser (Classilla maintainer) is the closest prior art
for the **proxy** part of macSSL's plan. Tagline "TLS for the
Internet of Old Things." Targets pre-C99 compilers and old
architectures. The `carl` utility has SOCKSv4 support and an
HTTP/HTTPS proxy mode for old browsers that don't insist on
`CONNECT`; the README explicitly lists Classilla 9.3.4b among the
browsers that work against it.

That last point is load-bearing for macSSL: **Classilla can drive a
plain-HTTP-proxy that does TLS upstream**. We don't have to invent
or speculate that behaviour. The product idea is already validated
against a real browser, in the wild.

Where Crypto Ancienne diverges from macSSL: its Classic Mac build is
an **MPW MrC command-line tool using GUSI**, with the README warning
that MrC can generate incorrect code (optimization disabled to
mitigate) and that MPW shell stack allotment must be increased. So
it's a different toolchain, a different runtime model, and a
different deployment shape (MPW shell tool rather than Carbon
Toolbox app). macSSL is the **native Carbon / Open Transport** path
for users who don't want MPW in the loop.

### What's not worth chasing

- **OpenSSL on Classic Mac** — too large, depends on POSIX surface
  that doesn't exist.
- **GnuTLS, NSS, wolfSSL, MatrixSSL ports** — none have a
  pre-existing OS 9 port; porting from scratch is more work than
  using BearSSL.
- **Apple Keychain / old Security framework APIs** — Carbon-era
  surface that doesn't reach modern TLS.
- **Open Transport trap-patching extensions** — a different
  architectural approach (system-wide TLS interception) that doesn't
  match the proxy product.
- **OS X-only proxy tools** — wrong target OS.

### The open niche macSSL is filling

| Capability | Already proven by | Status |
|---|---|---|
| Native TLS on OS 9 | bbenchoff, Certainly, this project | proven |
| TLS 1.3 on OS 9 | Certainly | proven |
| CW8 + Classic Mac TLS | bbenchoff, this project | proven |
| Old-browser HTTPS via plain-HTTP proxy | Crypto Ancienne (MPW shell) | partly proven |
| **Native Carbon / Open Transport local HTTPS-fetching proxy for arbitrary OS 9 browsers** | — | **open** |

That last row is what macSSL is for. The other rows are reference
points that say the components work; the assembly is novel.

```
Classic browser / OS 9 app
        |  plain HTTP proxy request
        v
   127.0.0.1:8765
        |
        v
   MacSSL Proxy (this project, Carbon app)
        |  Open Transport TCP
        v
   BearSSL TLS client
        |
        v
   remote HTTPS server
```

## Current status (2026-05-19)

```
Stage 0   audit + vendor                    COMPLETE
Stage A   BearSSL static init / smoke       COMPLETE  G3 OS 9.1
Stage A.5 CW8 PPC mul64 codegen probe       COMPLETE  G3 OS 9.1
Stage B1  OT TCP connect (example.com:443)  COMPLETE  G3 OS 9.1
Stage B2  BearSSL insecure handshake        COMPLETE  G3 OS 9.1  (0xCCA9)
Stage B3  validated TLS via embedded roots  COMPLETE  G3 OS 9.1  (google.com)
Stage B4  HTTPS GET decrypted end-to-end    COMPLETE  G3 OS 9.1  (95B body)
Stage B5  MacSurf integration notes (doc)   COMPLETE
Stage C   local HTTP proxy app              ABANDONED — see below
Stage D   library mode (OSTLS_Fetch API)    COMPLETE  (regression harness wires through OSTLS_Fetch)
```

Public library surface: [`os9/ostls_fetch.h`](os9/ostls_fetch.h).
Full API doc: [`docs/macssl-library-api.md`](docs/macssl-library-api.md).
v1 limitations called out there explicitly (synchronous, HTTP/1.0
only, no streaming callback yet, Stage A insecure entropy stub).

> **DO NOT re-enable the Stage C listener code unless targeting a
> non-Carbon (MPW / pre-Carbon OT / Retro68 classic) build or a
> different process model.** The 14-round investigation report at
> [`docs/carbon-ot-passive-bind-finding.md`](docs/carbon-ot-passive-bind-finding.md)
> documents why. The C1 source is archived at
> `os9/archive/ostls_c1_listener_carbon_cfm_abandoned.{h,c}` for git
> history; the Stage B4 source is similarly at
> `os9/archive/ostls_b4_https_get_superseded.{h,c}` since the library
> entry point `OSTLS_Fetch` supersedes it.

### Stage C abandoned — Carbon CFM cannot do passive OTBind

Fourteen hardware iteration rounds (fixes16..fixes34) and a research
sweep across Apple Tech Notes, Inside Macintosh, the OT result-codes
appendix, and every preserved Apple sample archive established that
**`OTOpenEndpointInContext` endpoints categorically reject
caller-chosen `InetAddress` in `OTBind`**, regardless of port, host,
qlen, sync vs async, or protocol stack. Only `OTBind(NULL,NULL)` and
`OTBind({ addr=NULL, qlen=N })` succeed — and the latter binds to
whatever ephemeral port OT picks (returned 49417 / 49423 / 49433
across runs).

The "local proxy on port 8765" architecture is impossible on this
platform. No published Carbon CFM TCP server exists in any archive;
Apple's own HTTP Server sample is pre-Carbon (uses `OTAsyncOpenEndpoint`
without `InContext`). Full investigation report:
[docs/carbon-ot-passive-bind-finding.md](docs/carbon-ot-passive-bind-finding.md).

**The pivot:** macSSL ships as a static C library, MacSurf (and any
other classic-Mac browser project) links it directly. The Stage B4
fetch path is the library API surface in waiting. The
[B5 integration notes](docs/macssl-integration-notes.md) already lay
out the integration mechanics and the per-fetch memory footprint
(~50 KB, comfortable in a 16 MB Carbon partition).

**Baseline frozen at Stage B4 — native validated HTTPS GET works on
real Mac OS 9 PowerPC hardware.** Cipher suite negotiated and accepted
by the engine: `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)`,
TLS 1.2, validated against five embedded trust anchors (Amazon Root
CA 1, DigiCert Global Root G2, GTS Root R1, GTS Root R4 EC P-384, ISRG
Root X1). The full run log lives at
[docs/runs/2026-05-19-b4-google-ok.txt](docs/runs/2026-05-19-b4-google-ok.txt).

The project is past the crypto-risk phase. Remaining work is product /
proxy engineering. See
[docs/macssl-integration-notes.md](docs/macssl-integration-notes.md)
for the MacSurf-side integration design and Stage C plan.

## Layout

```
macSSL/
  README.md                  -- you are here (high-level + status)
  AUDIT.md                   -- Stage 0/A audit findings and closure note
  deep-research-report.md    -- BearSSL + OT design rationale
  bearssl/                   -- vendored upstream (commit 7bea48e5)
    inc/                     -- public headers (13 .h)
    src/                     -- crypto core, ssl, x509 (filtered for CW8/PPC)
    LICENSE.txt              -- BearSSL MIT-style license (legally required)
  os9/                       -- OS 9 integration layer (toolchain-independent)
    ostls_cw8_prefix.h       -- CW8 build-config shim (inline=empty, BR_* knobs)
    ostls_entropy.h/.c       -- Stage A insecure entropy stub
    ostls_smoketest.h/.c     -- Stage A non-network smoke test
    (later: ostls_socket, ostls_transport, ostls_proxy, ostls_trust)
  MacSSLTest/                -- standalone Stage A validation Carbon app
    main.c                   -- toolbox init + smoke test + result window
    macssltest_prefix.h      -- CW8 project prefix
    MacSSLTest.rsrc          -- binary 'carb'(0) resource
    README.md                -- how to set up the .mcp on the Mac
  tools/
    audit_cw8_compat.py      -- Stage 0 audit tool
    audit_report.json        -- full JSON audit output
    make_bearssl_filelist.py -- emits the 253-file BearSSL inclusion list
    make_carb_rsrc.py        -- emits a 'carb'(0) resource fork
    bearssl_cw8_files.txt    -- the 253 BearSSL .c files to compile
    bearssl_cw8_excluded.txt -- 41 excluded .c files with reasons
    bearssl_cw8_manifest.md  -- human-readable grouped manifest
    probes/ppc_mul64/        -- Stage A.5 mul64 codegen probe
```

## Why a local proxy, not a library

Three approaches were considered before settling on the proxy:

| Approach | Verdict |
|---|---|
| In-browser TLS library each browser links | Rejected — defeats "any browser works for free." Classilla and iCab can't / won't be modified. |
| System extension patching Open Transport traps | Rejected — wrong abstraction. Browsers using port 443 expect to do their own TLS; intercepting them would confuse, not help. |
| **Local HTTP proxy at `127.0.0.1:8765`** | **Adopted.** Every classic-Mac HTTP-capable client already supports proxy config (it's how the existing Go proxy at `116.202.231.103:8765` is used). Cleanest abstraction. |

The proxy is essentially the existing Go proxy at `proxy/`, **rewritten
in C using BearSSL, running natively on OS 9 itself** — so users don't
need a remote VPS.

## Why BearSSL

The deep-research report (`deep-research-report.md`) lays out the full case.
The short version:

- BearSSL's generic engine is **already a state machine** with caller-driven
  `sendrec` / `recvrec` / `sendapp` / `recvapp` channels. Maps onto a
  cooperative OS 9 event loop with no internal blocking, no threads, and
  no hidden network calls.
- The engine, X.509 context, and I/O buffer are all **caller-allocated**.
  Critical for OS 9 where heap behaviour matters and per-socket state
  must not live on deep call stacks.
- BearSSL's X.509 minimal validator supports **local trust anchors** and
  **known-key direct trust**, which is exactly the trust model a classic
  Mac needs (no live OCSP / CRL fetches, ship our own CA bundle, allow
  user pinning of self-hosted hosts).

## Why CodeWarrior 8

The deep-research report recommends Retro68 + GCC. That is correct for a
greenfield OS 9 TLS library targeting modern cross-compilation workflows.
**It is not correct for this project at v0.1:**

- CW8 is the known-working, on-machine OS 9 toolchain. Same one MacSurf
  uses to ship working binaries today.
- Retro68 stays as a Linux-side **pre-flight syntax checker** (the same
  way MacSurf uses it) — every new `.c` file is verified with
  `gcc -std=c89 -pedantic-errors -Dinline=` before being shipped to the Mac.
- Retro68 / PEF shared library packaging can come back later if there is
  a real reason to ship macSSL as a separately-linked fragment.

## Stage A validation gate

The next-thing-to-do is on the Mac:

1. Unzip [`macSSL.zip`](../macSSL.zip) at the macsurf-source root.
2. Follow [`MacSSLTest/README.md`](MacSSLTest/README.md) to create
   `MacSSLTest.mcp` in CW8 and build it.
3. Run the resulting `MacSSLTest` app on G3 / OS 9.1.
4. Run it again on G4 / OS 9.2.2.
5. Run [`tools/probes/ppc_mul64/`](tools/probes/ppc_mul64/) as a
   separate small CW8 project — six-cell matrix (G3 + G4 × 3 optimisation
   levels).

When both gates close: Stage B / C / D unblock (`OSTLSSocket` +
HTTP proxy listener + first real HTTPS fetch).

## Running the audit again (Linux)

```sh
cd /home/patrick/Webs/macsurf/macSSL
python3 tools/audit_cw8_compat.py --root bearssl --json tools/audit_report.json --top 12
python3 tools/make_bearssl_filelist.py
```

## Reading order

1. `deep-research-report.md` §"Executive summary" + §"BearSSL adaptation
   strategy" — design rationale.
2. `AUDIT.md` — audit results + Stage A/A.5 closure note + Stage B shape.
3. `MacSSLTest/README.md` — how to validate on real hardware.
4. `bearssl/inc/bearssl_ssl.h` — the engine API the proxy will drive.
