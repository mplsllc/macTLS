/*
 * tls13_handshake.h — TLS 1.3 handshake state machine types
 */

#ifndef OSTLS_TLS13_HANDSHAKE_H
#define OSTLS_TLS13_HANDSHAKE_H

#include "bearssl.h"
#include <stdint.h>
#include <stddef.h>
#include "ostls_tls13_keysched.h"
#include "ostls_tls13_record.h"

/* Handshake message types (RFC 8446 Section 4) */
#define TLS13_HT_CLIENT_HELLO          1
#define TLS13_HT_SERVER_HELLO          2
#define TLS13_HT_NEW_SESSION_TICKET    4
#define TLS13_HT_ENCRYPTED_EXTENSIONS  8
#define TLS13_HT_CERTIFICATE          11
#define TLS13_HT_CERTIFICATE_REQUEST  13
#define TLS13_HT_CERTIFICATE_VERIFY   15
#define TLS13_HT_FINISHED             20
#define TLS13_HT_KEY_UPDATE           24
#define TLS13_HT_MESSAGE_HASH        254

/* TLS versions */
#define TLS13_VERSION  0x0304
#define TLS12_VERSION  0x0303

/* TLS 1.3 cipher suite IDs */
#define TLS13_AES_128_GCM_SHA256       0x1301
#define TLS13_AES_256_GCM_SHA384       0x1302
#define TLS13_CHACHA20_POLY1305_SHA256 0x1303

/* Extension types */
#define TLS13_EXT_SERVER_NAME           0
#define TLS13_EXT_SUPPORTED_GROUPS     10
#define TLS13_EXT_SIGNATURE_ALGORITHMS 13
#define TLS13_EXT_SUPPORTED_VERSIONS   43
#define TLS13_EXT_COOKIE               44
#define TLS13_EXT_KEY_SHARE            51

/* Signature schemes */
#define TLS13_SIG_RSA_PSS_RSAE_SHA256      0x0804
#define TLS13_SIG_RSA_PSS_RSAE_SHA384      0x0805
#define TLS13_SIG_ECDSA_SECP256R1_SHA256   0x0403
#define TLS13_SIG_ECDSA_SECP384R1_SHA384   0x0503
#define TLS13_SIG_RSA_PKCS1_SHA256         0x0401
#define TLS13_SIG_RSA_PKCS1_SHA384         0x0501

/* Named groups */
#define TLS13_GROUP_X25519  0x001D

/* Handshake state machine states */
typedef enum {
    kTLS13_SendClientHello,
    kTLS13_SendCCS,
    kTLS13_RecvServerHello,
    kTLS13_RecvEncryptedExtensions,
    kTLS13_RecvCertRequestOrCert,
    kTLS13_RecvCertificate,
    kTLS13_RecvCertificateVerify,
    kTLS13_RecvFinished,
    kTLS13_SendFinished,
    kTLS13_Complete
} tls13_hs_state;

/* Return values from handshake state handlers */
typedef enum {
    kTLS13_OK,          /* state completed, advance to next */
    kTLS13_WantRead,    /* need more data from network */
    kTLS13_WantWrite,   /* have data to send */
    kTLS13_Fallback12,  /* server chose TLS 1.2, fall back */
    kTLS13_Error        /* handshake failed */
} tls13_hs_result;

/* Transcript hash context */
typedef struct {
    br_sha256_context sha256;
    br_sha384_context sha384;
    const br_hash_class *hash;
    size_t hash_len;
} tls13_transcript;

void tls13_transcript_init(tls13_transcript *t, const br_hash_class *hash);
void tls13_transcript_update(tls13_transcript *t,
                             const void *data, size_t len);
void tls13_transcript_snapshot(const tls13_transcript *t,
                               void *out_hash);
/* Reset for HRR: replace transcript with Hash(message_hash construct) */
void tls13_transcript_reset_for_hrr(tls13_transcript *t);

/* Full TLS 1.3 handshake context */
typedef struct {
    tls13_hs_state      state;
    tls13_keysched      ks;
    tls13_transcript    transcript;
    tls13_record_ctx    read_ctx;    /* decrypt incoming records */
    tls13_record_ctx    write_ctx;   /* encrypt outgoing records */

    /* Ephemeral X25519 key pair */
    unsigned char       ecdhe_secret[32];
    unsigned char       ecdhe_public[32];

    /* Traffic secrets (kept for Finished key derivation) */
    unsigned char       client_hs_secret[64];
    unsigned char       server_hs_secret[64];

    /* Buffer for non-certificate handshake messages (outgoing) */
    unsigned char       msg_buf[4096];
    size_t              msg_len;
    size_t              msg_offset;

    /*
     * Length of a pre-read handshake message sitting in msg_buf
     * (for the RecvCertRequestOrCert handler to hand off to
     * RecvCertificate). SEPARATE from msg_len to avoid triggering
     * the outgoing-send pump path.
     */
    size_t              pending_recv_msg_len;

    /*
     * Plaintext buffer for decrypted incoming handshake records.
     * TLS 1.3 servers commonly pack multiple handshake messages into
     * a single encrypted record (EncryptedExtensions + Certificate +
     * CertificateVerify + Finished). We decrypt the full record into
     * this buffer, then consume handshake messages one at a time from
     * here, advancing plain_offset. When plain_offset == plain_len,
     * we decrypt the next record.
     */
    unsigned char       plain_buf[16384];
    size_t              plain_len;
    size_t              plain_offset;

    /* HRR cookie */
    unsigned char       cookie[256];
    size_t              cookie_len;

    /* Negotiated cipher suite */
    uint16_t            cipher_suite;
    int                 is_tls13;
    int                 hrr_received;

    int                 cert_request_received;

    /* X.509 validation context (pointer to MacTLS_Context's xc) */
    const br_x509_class **x509_ctx;

    /*
     * BearSSL engine pointer — used only for PRNG seeding during
     * ClientHello construction. The handshake does NOT drive record
     * I/O through this engine; that is done directly against a
     * caller-supplied recv buffer. This field is allowed to be NULL
     * if the caller arranges RNG seeding some other way.
     */
    br_ssl_engine_context *eng;

    /* Server's public key (from certificate, for CertificateVerify) */
    br_x509_pkey        server_pkey;
    /* Backing storage for server_pkey's pointer fields */
    unsigned char       server_pkey_data[520]; /* BR_X509_BUFSIZE_KEY */

    /* Error code from BearSSL (if handshake fails) */
    int                 error;
} tls13_hs_ctx;

/*
 * Main handshake driver — call repeatedly from the pump loop.
 *
 * recv_buf / recv_len is a caller-owned buffer holding raw bytes received
 * from the network. The handshake consumes complete TLS records from the
 * front of the buffer and slides the remaining bytes down, updating
 * *recv_len to reflect what's still unread. Callers should append newly
 * received bytes to recv_buf at offset *recv_len before calling this.
 */
tls13_hs_result tls13_handshake_step(tls13_hs_ctx *hs,
                                     unsigned char *recv_buf,
                                     size_t *recv_len,
                                     const char *hostname);

/* Initialize handshake context */
void tls13_handshake_init(tls13_hs_ctx *hs);

/* Handle post-handshake messages (NewSessionTicket, KeyUpdate).
 * Called when an encrypted record with inner content type handshake (22)
 * is received during the application data phase. */
tls13_hs_result tls13_handle_post_handshake(tls13_hs_ctx *hs,
                                            const unsigned char *data,
                                            size_t data_len);

#endif /* OSTLS_TLS13_HANDSHAKE_H */
