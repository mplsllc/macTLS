/*
 * ostls_entropy.h
 *
 * macEntropy -- entropy gathering for macTLS. See MACENTROPY_SCOPE.md.
 *
 * !!! NOT YET HARDWARE-VALIDATED -- DO NOT TREAT AS PRODUCTION-READY !!!
 *
 * Stage A (current): the pool is a running BearSSL SHA-256 context that
 * every source sample is folded into; seed extraction clones the pool,
 * mixes a domain-separation tag, finalises 32 bytes, and folds the
 * result back. The seed is injected into BearSSL's engine HMAC-DRBG.
 * This is a real cryptographic accumulator (it replaced a rotate-XOR
 * mix), but the subsystem is not finished: cold-start seed-file
 * persistence (Stage C), source breadth -- OT + key-latency jitter --
 * (Stage B), and statistical validation on real G3 hardware (Stage E)
 * are all still pending.
 *
 * OSTLS_ENTROPY_STAGE_A_INSECURE stays defined until Stage E passes, so
 * any code touching this layer trips a compile-time reminder that the
 * entropy subsystem has not yet been blessed. Remove it at Stage E.
 */

#ifndef OSTLS_ENTROPY_H
#define OSTLS_ENTROPY_H

#include "bearssl_ssl.h"

/* Compile-time reminder: entropy is not yet hardware-validated.
 * Removed when macEntropy Stage E (statistical validation) passes. */
#define OSTLS_ENTROPY_STAGE_A_INSECURE 1

/*
 * Inject entropy into a BearSSL SSL engine.
 *
 * In v0.1/v0.2 this was an insecure stub (Stage A).
 * In v1.0 this gathers data from the global entropy pool.
 */
int OSTLS_InjectEntropy(br_ssl_engine_context *eng);

/*
 * Gathers entropy from jittery sources:
 *   - Mouse position/delta
 *   - Keyboard latency jitter (if called from event loop)
 *   - System clock (TickCount/Microseconds)
 *
 * Should be called periodically (e.g. 60Hz from the app's idle loop).
 */
void OSTLS_CollectEntropy(void);

/*
 * Cold-start seed persistence (Stage C).
 *
 * OSTLS_LoadSeed reads the persisted seed file (Preferences folder) and
 * folds it into the pool. It is called automatically the first time the
 * pool is used, so cold-start benefit needs no host cooperation; it is
 * also exported for a host that wants to load explicitly at startup.
 *
 * OSTLS_SaveSeed extracts a fresh, domain-separated 32-byte seed and
 * writes it back. It fires automatically once per process on the first
 * entropy injection. A host SHOULD also call it at a clean shutdown to
 * persist the full session's accumulated entropy. The seed file is only
 * ever mixed in alongside live samples -- never trusted alone.
 */
void OSTLS_LoadSeed(void);
void OSTLS_SaveSeed(void);

/*
 * Source breadth + accounting (Stage B).
 *
 * OSTLS_StirTimer folds a fresh high-resolution timestamp (Microseconds
 * + TickCount) plus a caller hint into the pool. macTLS calls it at each
 * OTRcv that delivers bytes, so the unpredictable arrival timing of
 * every network packet during a fetch becomes entropy -- a high-rate
 * source that is genuinely jittery and needs no host cooperation. Safe
 * to call frequently; it is pure computation plus two clock reads.
 *
 * OSTLS_EntropySampleCount returns the number of source samples folded
 * into the pool so far -- a coarse accounting signal (not a true
 * entropy estimate) for telling whether the pool has been fed.
 */
void OSTLS_StirTimer(unsigned long hint);
unsigned long OSTLS_EntropySampleCount(void);

/*
 * Statistical self-test (Stage E). Extracts a batch of seeds and checks
 * for non-degenerate output: successive seeds differ, byte values spread
 * across the range, bit balance near 50%. Returns 0 on pass, nonzero on
 * fail, and writes a 32-bit fingerprint of the batch to *out_fp (NULL is
 * allowed). Compare the fingerprint across separate launches: it MUST
 * differ, which is the real proof that per-run entropy is incorporated.
 * The within-run checks only guard against degenerate output, since a
 * SHA-256 hash chain looks random regardless of input entropy.
 */
int OSTLS_EntropySelfTest(unsigned long *out_fp);

#endif /* OSTLS_ENTROPY_H */
