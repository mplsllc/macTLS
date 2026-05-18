# macSSL

Native TLS for Mac OS 9, built on **BearSSL**, shipping as a standalone
**local HTTP proxy Carbon app** that any OS 9 browser can configure as
its HTTP proxy. The proxy strips TLS on behalf of clients: it accepts
plain HTTP, fetches the upstream over HTTPS via BearSSL + Open
Transport, and returns plain HTTP to the caller.

This is a **system-wide service**, not a library that any specific
browser is forced to link. Classilla, iCab, MacSurf, and anything else
that honours HTTP proxy configuration gets HTTPS for free.

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

## Current status (2026-05-18)

```
Stage 0:                     COMPLETE  (audit + vendor)
Stage A (source-side):       COMPLETE  (CW8 prefix, file list, entropy, smoke)
Stage A test app:            COMPLETE  (MacSSLTest/ — bare Carbon harness)
Stage A Mac validation:      PENDING   (build MacSSLTest.mcp, smoke OK on G3 + G4)
Stage A.5 mul64 validation:  PENDING   (probe G3 + G4 across 3 optimisations)
Stage B (OSTLSSocket):       BLOCKED   until both Mac validations land
Stage C (HTTP listener):     BLOCKED
Stage D (HTTPS fetch):       BLOCKED
Stage E+ (compat, packaging):BLOCKED
```

Source-side work is **frozen** until the Mac validation lands. Each
stage gate is verified independently before the next begins.

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
