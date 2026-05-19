/*
 * ostls_b3_anchors.h
 *
 * Stage B3 embedded X.509 trust anchors for MacSSLTest. Five
 * well-known root CAs that cover Google, Amazon, Let's Encrypt and
 * DigiCert-signed leaf certificates:
 *
 *   TA0  Amazon Root CA 1                     RSA-2048   exp 2038-01-17
 *   TA1  DigiCert Global Root G2              RSA-2048   exp 2038-01-15
 *   TA2  GTS Root R1   (Google primary RSA)   RSA-4096   exp 2036-06-22
 *   TA3  GTS Root R4   (Google ECDSA chain)   EC P-384   exp 2036-06-22
 *   TA4  ISRG Root X1  (Let's Encrypt)        RSA-4096   exp 2035-06-04
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

#define OSTLS_B3_NUM_ANCHORS  5

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
