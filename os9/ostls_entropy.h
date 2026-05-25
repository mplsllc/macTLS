/*
 * ostls_entropy.h
 *
 * Stage A entropy stub for macTLS.
 *
 * !!! THIS IS NOT CRYPTOGRAPHICALLY SECURE !!!
 *
 * The Stage A implementation mixes weak, partially-deterministic sources
 * (TickCount, Microseconds, current mouse position, stack-address noise,
 * a fixed Stage-A identifier) to satisfy BearSSL's "did you give me any
 * entropy at all" check. It is intentionally just enough to make
 * br_ssl_client_reset() not return BR_ERR_NO_RANDOM during the smoke
 * test, no more. The macro OSTLS_ENTROPY_STAGE_A_INSECURE is exported
 * so any code touching this layer trips a compile-time reminder.
 *
 * Production entropy will be its own subsystem in a later stage, drawing
 * from: mouse-delta hashing across an idle interval, key-down latency
 * jitter, OT notifier-tick jitter, and a persisted seed file rolled on
 * clean shutdown. That work belongs after the first hardcoded-host
 * HTTPS handshake succeeds.
 */

#ifndef OSTLS_ENTROPY_H
#define OSTLS_ENTROPY_H

#include "bearssl_ssl.h"

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
