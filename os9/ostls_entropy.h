/*
 * ostls_entropy.h
 *
 * Stage A entropy stub for macSSL.
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

#define OSTLS_ENTROPY_STAGE_A_INSECURE 1

/*
 * Inject Stage A weak entropy into a BearSSL SSL engine. Pulls a small
 * number of bytes from TickCount, Microseconds, mouse position, stack
 * address, and a fixed Stage-A identifier, and feeds them through
 * br_ssl_engine_inject_entropy(). Safe to call before
 * br_ssl_client_reset().
 *
 * Returns 0 on success, a non-zero OSStatus-like value on failure
 * (currently always returns 0; reserved for future expansion).
 */
int OSTLS_InjectStageAEntropy(br_ssl_engine_context *eng);

#endif /* OSTLS_ENTROPY_H */
