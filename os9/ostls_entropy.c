/*
 * ostls_entropy.c -- macTLS entropy gathering.
 *
 * macEntropy Stage A: cryptographic accumulator.
 *
 * The pool is a running BearSSL SHA-256 context that every source
 * sample is folded into via br_sha256_update. Seed extraction clones
 * the pool, mixes a domain-separation tag, and finalises the clone to
 * produce 32 bytes; the extracted seed is then folded back into the
 * live pool so successive extractions are independent and the output
 * is never the raw running hash. The 32-byte seed is injected into
 * BearSSL's engine, which runs its own HMAC-DRBG downstream -- macTLS
 * supplies the seed material, it does not implement the generator.
 *
 * This replaces the Stage-0 rotate-XOR mix, which was not a
 * cryptographic accumulator. It is NOT yet the v1.0 subsystem: cold-
 * start seed-file persistence (Stage C), source breadth (Stage B), and
 * hardware statistical validation (Stage E) are still pending, so
 * OSTLS_ENTROPY_STAGE_A_INSECURE stays defined as a compile-time
 * reminder until Stage E passes. See MACENTROPY_SCOPE.md.
 */

#include "ostls_entropy.h"
#include "bearssl_hash.h"

#ifdef __MWERKS__
#include <Types.h>
#include <Events.h>
#include <Timer.h>
#include <Quickdraw.h>
#else
#include <stdint.h>
typedef uint32_t UInt32;
typedef struct { UInt32 hi; UInt32 lo; } UnsignedWide;
typedef struct { short v; short h; } Point;
#endif

#include <string.h>

/* The entropy pool: a running SHA-256 context, never reset for the life
 * of the process. Every source sample is folded in via update(). */
static br_sha256_context g_pool;
static int    g_pool_init = 0;
static UInt32 g_sample_count = 0;
static Point  g_last_mouse = { 0, 0 };

static void
pool_ensure_init(void)
{
    if (!g_pool_init) {
        br_sha256_init(&g_pool);
        g_pool_init = 1;
    }
}

/* Fold one source sample into the pool. */
static void
pool_update(const void *data, size_t len)
{
    pool_ensure_init();
    br_sha256_update(&g_pool, data, len);
    g_sample_count++;
}

void
OSTLS_CollectEntropy(void)
{
    UInt32 ticks;
    UnsignedWide usec;
    Point mouse;

#ifdef __MWERKS__
    ticks = (UInt32)TickCount();
    Microseconds(&usec);
    GetMouse(&mouse);
#else
    ticks = 0;
    usec.hi = 0; usec.lo = 0;
    mouse.h = 0; mouse.v = 0;
#endif

    pool_update(&ticks, sizeof ticks);
    pool_update(&usec, sizeof usec);

    /* Only fold the mouse in when it moved -- a static position carries
     * no new entropy and would over-weight a constant value. */
    if (mouse.h != g_last_mouse.h || mouse.v != g_last_mouse.v) {
        pool_update(&mouse, sizeof mouse);
        g_last_mouse = mouse;
    }
}

int
OSTLS_InjectEntropy(br_ssl_engine_context *eng)
{
    int local_var;
    unsigned long stackaddr;
    UnsignedWide usec;
    br_sha256_context tmp;
    unsigned char seed[32];
    /* Domain-separation tag for extraction, so the extracted seed is a
     * distinct function from the running pool state. */
    static const unsigned char extract_tag[8] =
        { 'm', 'a', 'c', 'E', 'x', 't', 'r', 0 };

    if (eng == NULL) return -1;
    pool_ensure_init();

    /* Fold fresh volatile state into the pool just before extraction so
     * even a caller that never ran CollectEntropy gets some live noise. */
    stackaddr = (unsigned long)(void *)&local_var;
    pool_update(&stackaddr, sizeof stackaddr);
#ifdef __MWERKS__
    Microseconds(&usec);
#else
    usec.hi = 0; usec.lo = 0;
#endif
    pool_update(&usec, sizeof usec);
    pool_update(&g_sample_count, sizeof g_sample_count);

    /* Extract: clone the pool, mix the tag into the clone, finalise. The
     * clone leaves the live pool untouched (br_sha256_out is const). */
    tmp = g_pool;
    br_sha256_update(&tmp, extract_tag, sizeof extract_tag);
    br_sha256_out(&tmp, seed);

    /* Fold the extracted seed back into the live pool so the next
     * extraction is independent of this one. */
    br_sha256_update(&g_pool, seed, sizeof seed);

    br_ssl_engine_inject_entropy(eng, seed, sizeof seed);
    return 0;
}
