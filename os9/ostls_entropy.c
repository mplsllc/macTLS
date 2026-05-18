/*
 * ostls_entropy.c -- Stage A INSECURE entropy stub. See ostls_entropy.h.
 *
 * Mixes weak sources to satisfy BearSSL's "entropy must be provided"
 * gate during the Stage A smoke test. NOT production-grade. The bytes
 * gathered here have nothing like 128 bits of real entropy; the goal is
 * only to get past br_ssl_engine_inject_entropy() so the smoke test can
 * observe context initialization end-to-end.
 *
 * Stage A inputs:
 *   - TickCount()       (1/60 s ticks since boot; ~32-bit)
 *   - Microseconds()    (microsecond counter; ~64-bit)
 *   - LMGetMouse()      (current cursor position; weak after boot)
 *   - &local             (stack frame address; varies with caller)
 *   - "macSSL/stage-A"  (fixed string; differentiates this build)
 *
 * Production work belongs in a later stage:
 *   - Mouse delta hashing across an idle window
 *   - Key-down latency jitter
 *   - OT notifier tick jitter
 *   - Persisted seed file rolled at clean shutdown
 *   - First-run "wiggle the mouse" gathering dialog
 */

#include "ostls_entropy.h"

#ifdef __MWERKS__
#include <Types.h>
#include <Events.h>
#include <LowMem.h>
#include <Timer.h>
#else
/* Non-CW8 path (Linux syntax check). Provide stub types so the file
 * still parses under retro68 or `gcc -fsyntax-only`. These are NOT used
 * at runtime -- the CW8 build is the only target that actually links
 * this. */
#include <stdint.h>
typedef uint32_t UInt32;
typedef int16_t SInt16;
typedef struct { SInt16 v; SInt16 h; } Point;
typedef struct { UInt32 hi; UInt32 lo; } UnsignedWide;
#endif

#include <string.h>

/* Forward decls so we compile under both CW8 and the Linux audit path. */
#ifdef __MWERKS__
/* Toolbox prototypes come from the headers above. */
#else
static UInt32 TickCount(void) { return 0; }
static void Microseconds(UnsignedWide *w) { w->hi = 0; w->lo = 0; }
static Point LMGetMouse(void) { Point p; p.v = 0; p.h = 0; return p; }
#endif


/*
 * Pack the weak Stage A entropy sources into a fixed-size buffer and
 * inject. The buffer is intentionally small (32 bytes) -- this is
 * enough for BearSSL's gate, not enough for real security.
 */
int
OSTLS_InjectStageAEntropy(br_ssl_engine_context *eng)
{
    unsigned char buf[32];
    UInt32 ticks;
    UnsignedWide usec;
    Point mouse;
    unsigned long stackaddr;
    int local_var;
    static const char tag[] = "macSSL/stage-A";

    if (eng == NULL) {
        return -1;
    }

    /* Collect sources. */
    ticks = TickCount();
    Microseconds(&usec);
#ifdef __MWERKS__
    mouse = LMGetMouse();
#else
    mouse = LMGetMouse();
#endif
    stackaddr = (unsigned long)(void *)&local_var;

    /* Pack into buf[]. Byte order is internally consistent for this
     * build; cross-build reproducibility is not a concern for an
     * intentionally-insecure stub. */
    memset(buf, 0, sizeof buf);

    /* bytes 0-3: TickCount */
    buf[0] = (unsigned char)(ticks >> 24);
    buf[1] = (unsigned char)(ticks >> 16);
    buf[2] = (unsigned char)(ticks >>  8);
    buf[3] = (unsigned char)(ticks);

    /* bytes 4-11: Microseconds (8 bytes, big-endian) */
    buf[ 4] = (unsigned char)(usec.hi >> 24);
    buf[ 5] = (unsigned char)(usec.hi >> 16);
    buf[ 6] = (unsigned char)(usec.hi >>  8);
    buf[ 7] = (unsigned char)(usec.hi);
    buf[ 8] = (unsigned char)(usec.lo >> 24);
    buf[ 9] = (unsigned char)(usec.lo >> 16);
    buf[10] = (unsigned char)(usec.lo >>  8);
    buf[11] = (unsigned char)(usec.lo);

    /* bytes 12-15: mouse position (h then v, 2 bytes each) */
    buf[12] = (unsigned char)(mouse.h >> 8);
    buf[13] = (unsigned char)(mouse.h);
    buf[14] = (unsigned char)(mouse.v >> 8);
    buf[15] = (unsigned char)(mouse.v);

    /* bytes 16-19: stack address */
    buf[16] = (unsigned char)(stackaddr >> 24);
    buf[17] = (unsigned char)(stackaddr >> 16);
    buf[18] = (unsigned char)(stackaddr >>  8);
    buf[19] = (unsigned char)(stackaddr);

    /* bytes 20-31: Stage A tag (truncated/zero-padded; sizeof tag is 15
     * including the NUL, so this fits and leaves room). */
    memcpy(buf + 20, tag, sizeof tag > 12 ? 12 : sizeof tag);

    br_ssl_engine_inject_entropy(eng, buf, sizeof buf);
    return 0;
}
