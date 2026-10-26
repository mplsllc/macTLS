# Third-party notices

The root [MIT license](LICENSE) applies to macTLS-authored code only. The
components below retain their own licenses and notices.

## BearSSL

BearSSL is vendored in `bearssl/`. Its MIT license and copyright notice are
preserved in [bearssl/LICENSE.txt](bearssl/LICENSE.txt). Keep that notice with
copies or distributions containing BearSSL code.

## Certainly

The TLS 1.3 handshake, key schedule, and record modules in
`os9/ostls_tls13_handshake.c`, `os9/ostls_tls13_keysched.c`, and
`os9/ostls_tls13_record.c` were adapted from Certainly by Matt Baker
(`minorbug`). The original project is available at
https://github.com/minorbug/certainly. The adapted modules remain under the
following MIT notice:

MIT License

Copyright (c) 2026 Matt Baker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Mozilla CA certificate data

The trust anchors embedded in `os9/ostls_b3_anchors.c` were generated from
the Mozilla CA certificate bundle. They are certificate data, not macTLS
source code. The checked-in regeneration script documents the source bundle
and process; the root macTLS license does not replace any terms applicable to
that data.
