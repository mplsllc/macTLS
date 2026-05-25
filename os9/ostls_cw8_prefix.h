/*
 * ostls_cw8_prefix.h
 *
 * CW8 / CodeWarrior 8 PPC compatibility prefix for the vendored BearSSL
 * source tree at macTLS/bearssl/.
 *
 * This file is consumed by every translation unit compiling BearSSL .c
 * files under any CW8 project that links macTLS. It must be included
 * before any BearSSL header (in practice: set it as the project-level
 * prefix file, or include it from a project prefix like
 * mactlstest_prefix.h or macsurf_prefix.h).
 *
 * Two roles:
 *
 *   1. CW8 language-level workarounds (the audit-driven part).
 *      Currently a single keyword: `inline`.
 *
 *   2. BearSSL build-time configuration (the deliberate part).
 *      Force-disables every platform-specific path BearSSL might try to
 *      autodetect, and pins the 32-bit big-integer code path. CW8 PPC
 *      uses LP32 longs and does not define the GNU / Clang / MSC macros
 *      that BearSSL's inner.h consults for autodetection, so most of
 *      these would default to "off" anyway. We set them explicitly so
 *      the build configuration is self-documenting and survives any
 *      future change to inner.h's autodetection logic.
 *
 * Do NOT edit upstream BearSSL files to apply these settings. Keeping
 * the vendor tree pristine is policy for v0.1.
 */

#ifndef OSTLS_CW8_PREFIX_H
#define OSTLS_CW8_PREFIX_H

#ifdef __MWERKS__

/* ----------------------------------------------------------------- */
/* ostls_entropy.c compatibility                                     */
/* ----------------------------------------------------------------- */

/*
 * An older copy of ostls_entropy.c may call LMGetMouse() for entropy.
 * CW8 sees LMGetMouse as returning int (implicit, no header declaring it),
 * and rejects the assignment to Point with "illegal implicit conversion".
 * Override with a macro that returns a zero Point — mouse position
 * contributes nothing to Stage A's intentionally-insecure stub.
 */
#ifndef MACTLS_LMGetMouse_neutralised
#define MACTLS_LMGetMouse_neutralised
static Point mactls_zero_pt_; /* zero-initialized at file scope */
#define LMGetMouse() mactls_zero_pt_
#endif

/* ----------------------------------------------------------------- */
/* CW8 language compatibility                                        */
/* ----------------------------------------------------------------- */

/*
 * CW8 C89 does not accept the `inline` storage-class keyword. BearSSL
 * uses `static inline` extensively (audit: 113 occurrences across 8
 * headers, plus 67 more in 32-bit *.c files we will compile). Expanding
 * `inline` to empty makes `static inline` decay to plain `static`, which
 * is what every C89 compiler accepts. Each TU gets its own private copy
 * of the function. Code size grows; correctness is unaffected.
 */
#ifndef inline
#define inline
#endif

/* ----------------------------------------------------------------- */
/* BearSSL platform configuration (set explicitly, never autodetect) */
/* ----------------------------------------------------------------- */

/*
 * Force the 32-bit integer code path. PPC is 32-bit under CW8 (long is
 * 32 bits, LP32 model). Even if it were 64-bit-capable, the CW8 PPC
 * codegen for 64-bit shift-by-constant multiplies is known to be wrong
 * in MacSurf experience -- see CLAUDE.md "CW8 PPC miscompiles long long
 * multiply-by-constant" gotcha. Pin to BR_64=0.
 */
#ifndef BR_64
#define BR_64   0
#endif

/*
 * BR_LOMUL is the ARM Cortex-M "low-multiplier" hint. PPC has a full
 * 32x32->64 multiply (mullw + mulhwu), so leave this disabled.
 */
#ifndef BR_LOMUL
#define BR_LOMUL   0
#endif

/*
 * Constant-time 31-bit multiplication. PPC's mullw has constant timing
 * on every shipping G3/G4 core we target, so BR_CT_MUL31 is not strictly
 * required. However, Stage A is about correctness and build stability,
 * not performance. Enable it during Stage A to be safe, and revisit
 * after the i31_moddiv hardware probe in Stage A.5.
 */
#ifndef BR_CT_MUL31
#define BR_CT_MUL31   1
#endif

/* No alternate path for 15-bit multiplies. Default off. */
#ifndef BR_CT_MUL15
#define BR_CT_MUL15   0
#endif

/* No slow-multiply assumption. Default off. */
#ifndef BR_SLOW_MUL
#define BR_SLOW_MUL   0
#endif

#ifndef BR_SLOW_MUL15
#define BR_SLOW_MUL15   0
#endif

/*
 * Endianness / alignment. PPC is big-endian. CW8 PPC can do unaligned
 * loads, but via slow trap emulation -- treat unaligned access as
 * unavailable so BearSSL uses its byte-by-byte fallback. Same policy
 * MacSurf already uses elsewhere.
 */
#ifndef BR_BE_UNALIGNED
#define BR_BE_UNALIGNED   0
#endif

#ifndef BR_LE_UNALIGNED
#define BR_LE_UNALIGNED   0
#endif

/*
 * No x86 instruction-set extensions, no POWER8 crypto, no GCC/Clang
 * 128-bit integers, no MSC umul128 intrinsic. All of these would
 * default to off under CW8 because the gating macros (__GNUC__,
 * __clang__, _MSC_VER, BR_i386, BR_amd64) are all undefined, but we
 * set them explicitly so the build manifest is self-documenting.
 */
#ifndef BR_AES_X86NI
#define BR_AES_X86NI   0
#endif

#ifndef BR_SSE2
#define BR_SSE2   0
#endif

#ifndef BR_RDRAND
#define BR_RDRAND   0
#endif

#ifndef BR_POWER8
#define BR_POWER8   0
#endif

#ifndef BR_INT128
#define BR_INT128   0
#endif

#ifndef BR_UMUL128
#define BR_UMUL128   0
#endif

#ifndef BR_ARMEL_CORTEXM_GCC
#define BR_ARMEL_CORTEXM_GCC   0
#endif

/*
 * No OS entropy source. BearSSL would otherwise try /dev/urandom or
 * BCryptGenRandom; both are absent on OS 9. We provide our own seed
 * via ostls_entropy.c (Stage A: insecure stub; production: mouse +
 * key + tick jitter + persisted seed file).
 */
#ifndef BR_USE_URANDOM
#define BR_USE_URANDOM   0
#endif

#ifndef BR_USE_GETENTROPY
#define BR_USE_GETENTROPY   0
#endif

#ifndef BR_USE_WIN32_RAND
#define BR_USE_WIN32_RAND   0
#endif

/*
 * No OS time source. BearSSL's X.509 validator otherwise pulls time()
 * via BR_USE_UNIX_TIME or GetSystemTimeAsFileTime() via
 * BR_USE_WIN32_TIME. We will pass current time to br_x509_minimal_set_time()
 * explicitly from MacSurf using the OS 9 time APIs (post-Stage-A).
 */
#ifndef BR_USE_UNIX_TIME
#define BR_USE_UNIX_TIME   0
#endif

#ifndef BR_USE_WIN32_TIME
#define BR_USE_WIN32_TIME   0
#endif

/*
 * No GCC/Clang compiler-detection cascades. BearSSL's inner.h tests
 * __GNUC__ and __clang__; CW8 sets neither, so these would default off,
 * but make it explicit.
 */
#ifndef BR_GCC
#define BR_GCC   0
#endif

#ifndef BR_CLANG
#define BR_CLANG   0
#endif

#ifndef BR_MSC
#define BR_MSC   0
#endif

#endif /* __MWERKS__ */

#endif /* OSTLS_CW8_PREFIX_H */
