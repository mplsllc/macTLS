/*
 * test_tls13_keysched.c -- verify the TLS 1.3 key schedule against
 * RFC 8446 / RFC 8448 test vectors.
 *
 * Host build only (native cc, not CodeWarrior). The module under test
 * (os9/ostls_tls13_keysched.c) is C89 for CW8; this harness is plain
 * host C and just needs to link against BearSSL's hash + HMAC.
 *
 * Vectors adapted from Certainly's tests/host/test_keysched.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../os9/ostls_tls13_keysched.h"

static int failures = 0;

static void assert_bytes(const char *name, const void *expected,
                         const void *actual, size_t len)
{
    if (memcmp(expected, actual, len) != 0) {
        size_t i;
        printf("FAIL: %s\n", name);
        printf("  expected: ");
        for (i = 0; i < len; i++) printf("%02x", ((unsigned char*)expected)[i]);
        printf("\n  actual:   ");
        for (i = 0; i < len; i++) printf("%02x", ((unsigned char*)actual)[i]);
        printf("\n");
        failures++;
    } else {
        printf("PASS: %s\n", name);
    }
}

static void hex_to_bytes(const char *hex, unsigned char *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        out[i] = (unsigned char)b;
    }
}

/* SHA-256("") should produce the known hash. */
static void test_empty_hash(void)
{
    tls13_keysched ks;
    unsigned char expected[32];

    hex_to_bytes(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855",
        expected, 32);

    tls13_ks_init(&ks, &br_sha256_vtable);
    assert_bytes("SHA-256 empty hash", expected, ks.empty_hash, 32);
}

/* Early Secret from zeros (no PSK):
 * early_secret = HKDF-Extract(salt=0x00*32, IKM=0x00*32). */
static void test_early_secret(void)
{
    tls13_keysched ks;
    unsigned char expected[32];

    hex_to_bytes(
        "33ad0a1c607ec03b09e6cd9893680ce2"
        "10adf300aa1f2660e1b22e10f170f92a",
        expected, 32);

    tls13_ks_init(&ks, &br_sha256_vtable);
    tls13_ks_extract_early(&ks);
    assert_bytes("Early Secret (no PSK)", expected, ks.secret, 32);
}

/* Full key schedule with the RFC 8448 example handshake trace. */
static void test_handshake_secret(void)
{
    tls13_keysched ks;
    unsigned char shared_secret[32];
    unsigned char transcript_hash[32];
    unsigned char client_key[32], client_iv[12];
    unsigned char server_key[32], server_iv[12];

    /* DH shared secret from RFC 8448 Section 3 */
    hex_to_bytes(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d"
        "35e6d63f537563efd46272900f89492d",
        shared_secret, 32);

    /* Transcript hash of ClientHello + ServerHello from RFC 8448 */
    hex_to_bytes(
        "860c06edc07858ee8e78f0e7428c58ed"
        "d6b43f2ca3e6e95f02ed063cf0e1cad8",
        transcript_hash, 32);

    tls13_ks_init(&ks, &br_sha256_vtable);
    tls13_ks_extract_early(&ks);
    tls13_ks_extract_handshake(&ks, shared_secret, 32);

    {
        unsigned char expected_hs[32];
        hex_to_bytes(
            "1dc826e93606aa6fdc0aadc12f741b01"
            "046aa6b99f691ed221a9f0ca043fbeac",
            expected_hs, 32);
        assert_bytes("Handshake Secret", expected_hs, ks.secret, 32);
    }

    /* Derive handshake keys. RFC 8448 uses AES-128-GCM (16-byte key),
     * server handshake key 3fce516009c21727d0f2e4e86ee403bc. */
    tls13_ks_derive_handshake_keys(&ks, transcript_hash, 16,
                                    client_key, client_iv,
                                    server_key, server_iv,
                                    NULL, NULL);
    {
        unsigned char expected_skey[16];
        unsigned char expected_siv[12];
        hex_to_bytes("3fce516009c21727d0f2e4e86ee403bc",
                     expected_skey, 16);
        hex_to_bytes("5d313eb2671276ee13000b30", expected_siv, 12);
        assert_bytes("Server handshake key", expected_skey, server_key, 16);
        assert_bytes("Server handshake IV", expected_siv, server_iv, 12);
    }

    /* Client handshake key/iv from RFC 8448 -- this is the side we
     * encrypt the client Finished with, and never verified before. */
    {
        unsigned char expected_ckey[16];
        unsigned char expected_civ[12];
        hex_to_bytes("dbfaa693d1762c5b666af5d950258d01",
                     expected_ckey, 16);
        hex_to_bytes("5bd3c71b836e0b76bb73265f", expected_civ, 12);
        assert_bytes("Client handshake key", expected_ckey, client_key, 16);
        assert_bytes("Client handshake IV", expected_civ, client_iv, 12);
    }
}

int main(void)
{
    printf("=== TLS 1.3 Key Schedule Tests (macTLS) ===\n\n");

    test_empty_hash();
    test_early_secret();
    test_handshake_secret();

    printf("\n%d test(s) failed.\n", failures);
    return failures > 0 ? 1 : 0;
}
