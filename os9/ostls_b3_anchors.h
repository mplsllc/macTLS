/*
 * ostls_b3_anchors.h
 *
 * Stage B3 embedded X.509 trust anchors for MacSSLTest. Ten
 * well-known root CAs that cover Google (RSA + ECDSA chains),
 * Amazon, Let's Encrypt (RSA + ECDSA), DigiCert (RSA + ECDSA),
 * and Starfield Services. Set matches the prior-art project
 * Certainly (https://github.com/minorbug/certainly), which we
 * adopted after Stage B4 once the architectural pattern was
 * established:
 *
 *   TA0  Amazon Root CA 1                      RSA-2048   exp 2038-01-17
 *   TA1  DigiCert Global Root G2               RSA-2048   exp 2038-01-15
 *   TA2  GTS Root R1   (Google primary RSA)    RSA-4096   exp 2036-06-22
 *   TA3  GTS Root R4   (Google ECDSA, P-384)   EC P-384   exp 2036-06-22
 *   TA4  ISRG Root X1  (Let's Encrypt RSA)     RSA-4096   exp 2035-06-04
 *   TA5  ISRG Root X2  (Let's Encrypt ECDSA)   EC P-384   exp 2040-09-17
 *   TA6  GTS Root R2   (Google secondary RSA)  RSA-4096   exp 2036-06-22
 *   TA7  GTS Root R3   (Google ECDSA)          EC P-384   exp 2036-06-22
 *   TA8  DigiCert Global Root G3               EC P-384   exp 2038-01-15
 *   TA9  Starfield Services Root CA G2         RSA-2048   exp 2037-12-31
 *
 * Bytes were extracted from public PEMs via BearSSL's `brssl ta` tool
 * (built from the same vendored 7bea48e5 source tree) on 2026-05-19.
 *
 * The trust_anchor C-source emitted by brssl uses C99 designated
 * union initialisers (`.rsa = { ... }` / `.ec = { ... }`) which CW8
 * C89 will not accept. To keep the byte arrays static const while
 * still landing the EC anchor cleanly, we initialise the
 * br_x509_trust_anchor array at runtime via OSTLS_B3_GetAnchors.
 *
 * Rotation: BearSSL only consults the ROOT anchor by Distinguished
 * Name match against the chain the server presents. As long as the
 * server's chain still terminates in one of these five roots, B3
 * keeps validating. When a root is decommissioned (typically a year
 * or more of advance notice in the CA/B Forum) we rebuild this file
 * from a fresh brssl ta run.
 */

#ifndef OSTLS_B3_ANCHORS_H
#define OSTLS_B3_ANCHORS_H

#include <stddef.h>     /* size_t */

/*
 * BearSSL's trust-anchor typedef is anonymous-struct-derived rather
 * than a forward-declarable tag, so we pull in bearssl_x509.h here.
 * Callers of this header already need bearssl.h anyway.
 */
#include "bearssl_x509.h"

#define OSTLS_B3_NUM_ANCHORS  10

/*
 * Return a pointer to the populated, ready-to-use trust-anchor
 * array and its count. The pointer is to a static-lifetime array
 * inside ostls_b3_anchors.c; the caller does NOT own the storage.
 * The first call lazily initialises the array; subsequent calls
 * return the same pointer with no work.
 */
void OSTLS_B3_GetAnchors(const br_x509_trust_anchor **out_anchors,
                         size_t *out_count);

#endif /* OSTLS_B3_ANCHORS_H */
