/*
 * macssltest_prefix.h
 *
 * CodeWarrior 8 project prefix for the MacSSLTest standalone Carbon
 * app. This file is injected before every translation unit in
 * MacSSLTest.mcp -- including all 253 vendored BearSSL .c files and
 * the two macSSL/os9 sources.
 *
 * Mirrors the relevant subset of MacSurf's macsurf_prefix.h, minus
 * NetSurf-specific defines. Adds the macSSL CW8 compatibility shim so
 * BearSSL builds cleanly without upstream edits.
 *
 * In the CW8 IDE: Edit -> MacSSLTest Settings -> C/C++ Language ->
 * Prefix File: macssltest_prefix.h
 */

#ifndef MACSSLTEST_PREFIX_H
#define MACSSLTEST_PREFIX_H

/*
 * MacTypes.h must come first to lock in Apple's bool / true / false
 * definitions before any other header tries to redefine them. Same
 * discipline MacSurf uses.
 */
#include <MacTypes.h>

#ifndef __MACOS9__
#define __MACOS9__              1
#endif

/* CW8 needs TARGET_API_MAC_CARBON=1 before any system header sees it;
 * Retro68's multiversal headers preset it to 0. Guard the define so
 * either toolchain proceeds without redefinition warnings. */
#ifndef TARGET_API_MAC_CARBON
#define TARGET_API_MAC_CARBON   1
#endif

/* No IPv6 on classic Mac OS. */
#ifndef NO_IPV6
#define NO_IPV6                 1
#endif

/*
 * Pull in the BearSSL CW8 compatibility shim. This sets `#define inline`
 * to empty (CW8 C89 does not accept the inline keyword) and pins every
 * BR_* platform-config macro so BearSSL's autodetection cannot drag in
 * x86 / POWER8 / Linux paths.
 */
#include "ostls_cw8_prefix.h"

#endif /* MACSSLTEST_PREFIX_H */
