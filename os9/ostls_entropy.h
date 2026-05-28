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

#endif /* OSTLS_ENTROPY_H */
