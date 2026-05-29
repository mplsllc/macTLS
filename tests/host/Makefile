# Host-side unit tests for macTLS's portable code (key schedule, record
# layer, etc.). Built with the native compiler, NOT CodeWarrior -- these
# exercise the platform-independent crypto against known test vectors so
# we can verify it on Linux before any Mac is involved.
#
#   make test
#
# The modules under test are C89 (they also compile under CW8); this
# harness is plain host C linked against BearSSL's hash + HMAC + codec.

BEARSSL = ../../bearssl
CFLAGS  = -std=c99 -Wall -I$(BEARSSL)/inc -I$(BEARSSL)/src
BSSL    = $(wildcard $(BEARSSL)/src/hash/*.c $(BEARSSL)/src/mac/*.c \
                     $(BEARSSL)/src/codec/*.c $(BEARSSL)/src/symcipher/*.c \
                     $(BEARSSL)/src/aead/*.c $(BEARSSL)/src/int/*.c)

TESTS = test_tls13_keysched test_tls13_record

test: $(TESTS)
	@for t in $(TESTS); do echo "--- $$t ---"; ./$$t || exit 1; done

test_tls13_keysched: test_tls13_keysched.c ../../os9/ostls_tls13_keysched.c
	$(CC) $(CFLAGS) test_tls13_keysched.c ../../os9/ostls_tls13_keysched.c $(BSSL) -o $@

test_tls13_record: test_tls13_record.c ../../os9/ostls_tls13_record.c
	$(CC) $(CFLAGS) test_tls13_record.c ../../os9/ostls_tls13_record.c $(BSSL) -o $@

clean:
	rm -f $(TESTS)

.PHONY: test clean
