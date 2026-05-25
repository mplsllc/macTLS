/*
 * ostls_entropy.c -- macTLS production entropy gathering.
 *
 * Implements the v1.0 entropy plan:
 *   - Mouse position and delta hashing.
 *   - Microsecond-timer jitter.
 *   - Stack address noise.
 *   - Continuous accumulation into a 32-byte global pool.
 *
 * This pool is injected into BearSSL whenever a new connection starts.
 */

#include "ostls_entropy.h"

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

/* Global entropy pool (32 bytes). Accumulated over time. */
static unsigned char g_entropy_pool[32];
static UInt32 g_entropy_counter = 0;
static Point g_last_mouse = { 0, 0 };

/*
 * Simple hash-mix: rotate the pool and XOR in new bytes.
 */
static void
entropy_mix(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t i;
    for (i = 0; i < len; i++) {
        /* Rotate the pool by 1 bit + counter. */
        unsigned char carry = (g_entropy_pool[0] & 0x80) ? 1 : 0;
        int j;
        for (j = 0; j < 31; j++) {
            g_entropy_pool[j] = (unsigned char)((g_entropy_pool[j] << 1) | (g_entropy_pool[j+1] >> 7));
        }
        g_entropy_pool[31] = (unsigned char)((g_entropy_pool[31] << 1) | carry);

        /* XOR in the data byte. */
        g_entropy_pool[g_entropy_counter % 32] ^= p[i];
        g_entropy_counter++;
    }
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

    /* Mix in current state. */
    entropy_mix(&ticks, sizeof ticks);
    entropy_mix(&usec, sizeof usec);

    /* Only mix mouse if it moved, to avoid over-weighting static state. */
    if (mouse.h != g_last_mouse.h || mouse.v != g_last_mouse.v) {
        entropy_mix(&mouse, sizeof mouse);
        g_last_mouse = mouse;
    }
}

int
OSTLS_InjectEntropy(br_ssl_engine_context *eng)
{
    int local_var;
    unsigned long stackaddr;

    if (eng == NULL) return -1;

    /* One final mix of volatile state before injection. */
    stackaddr = (unsigned long)(void *)&local_var;
    entropy_mix(&stackaddr, sizeof stackaddr);

    /* Also mix in a few more microseconds to ensure fresh noise even
     * if the caller hasn't been calling CollectEntropy often. */
    {
        UnsignedWide usec;
#ifdef __MWERKS__
        Microseconds(&usec);
#else
        usec.hi = 0; usec.lo = 0;
#endif
        entropy_mix(&usec, sizeof usec);
    }

    br_ssl_engine_inject_entropy(eng, g_entropy_pool, sizeof g_entropy_pool);
    return 0;
}
