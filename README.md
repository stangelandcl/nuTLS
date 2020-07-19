# nuTLS

Minimal, modern, dependency-free TLS server / client library for Linux.

- Less than 30kLOC (21kLOC w/o comments) of clean, commented C code
- Comes with it's own fast MPI and crypto (based on tomcrypt, no homebrew stuff)
- Made for static linking, no dependencies and only about 200kB compiled code size
- Full TLS1.2 support, no TLS1.0 or TLS1.1. Less legacy, less attack surface. 
- Full TLS1.3 support on the server, experimental on client.
- No configuration options or ifdef jungle (only `-DDEBUG` for tracing) 
- Transparent, low level API (no suprise file reads - looking at you OpenSSL)
- Thread-safe, call `tls_init` once and then fork/thread to your heart's content

## Usage

Take a look at the `server.c` and `client.c` examples. Compile them with GCC or use musl-gcc for full static builds. Please read the comments in both files to learn how to setup certificates for trying the demos.

In your own projects, just include `nutls.c`.

:warning: nuTLS is **Linux x86-64 only**!

## Licensing

Almost all nuTLS code is in the Public Domain (see LICENSE). It is in large part based on work by Eduard Suica (TLS) and Tom St Denis (crypto and math).

The only exception is the implementation of Curve25519, which was created by Google. It's based on Public Domain code, but they chose to slap their license on it. So source or binary distributions of nuTLS need to come with the LICENSE.x25519.Google file, or reproduce it's contents somewhere else.

If someone has an equally clean implementation (from the Paper, using all it's optimizations, not using the reference implementation's weird code), please reach out. Or lobby Google to make the Curve25519 code Public Domain.

Curve25519 as used by nuTLS was implemented by Adam Langley, based on code by Daniel J. Bernstein.

## nuTLS for Servers

nuTLS applies the [linenoise](https://github.com/antirez/linenoise) philosophy to TLS libraries: Keep only the modern features, have a sensible default configuration. Thus it only ships with modern, strong ciphers (AES-GCM and ChaCha20), curves and DH parameters. In short, this means servers made with nuTLS will get full marks in TLS/SSL benchmarks:

![](https://elasticwaffle.com/img/nutls.png)

The above result is from the `server.c` example running in TLS1.2 mode. A 4096 bit RSA cert from LetsEncrypt was used.

In general, you should be running in TLS1.2 mode. TLS1.3 has some advantages but compatiblity is far from universal.

SSLabs Grading      | TLS1.3  | TLS1.2
------------------- | ------- | ------
Overall Rating      | A       | A+
Certificate         | 100%    | 100%
Protocol Support    | 100%    | 100%
Key Exchange        | 90%     | 100%
Cipher Strength     | 100%    | 100%

Curves (Supported Groups) | TLS1.3        | TLS1.2
------------------------- | ------------- | ------
secp256r1                 | ✓             | ✓
secp384r1                 | ✓             | ✓
x25519                    | ✓ (preferred) |

<details>
  <summary>Click to expand and read a rant about that one 90% score</summary>
  
  The usage of x25519 in TLS1.3 causes a downgrade to *Key Exchange* scoring. This is very misleading, as it is in no way less secure than secp\*, which originate from NIST-ECC. SSLabs scores any key exchange with less than 4096 bits as 90%. Since TLS1.2 doesn't offer x25519, it gets a perfect score. x25519 is equivalent to 3072 bits RSA, hence the downgrade.

  Here's why that grading system is just wrong:

  - All NIST curves are inherently questionable, as they are endorsed by RSA-breaking intelligence agencies (e.g. the NSA)
  - NIST intentionally excluded the strongest curve (`secp512r1`) from it's official recommendation for no technical reason. But because of this formality, `secp512r1` isn't considered "official", which caused a negative feedback loop which led to all vendors dropping support for it.
  - Curve25519 is faster, easier to implement and entirely unencumbered by any patents or licenses.

  There's another thing that NIST did to undermine security. The mandatory (and with that, fallback) curve is `secp256r1`, the least secure curve currently supported! Want to offer the best independent curve and the best NIST one (`secp384r1`)? Tough luck, you're now incompatible with a bunch of clients! Want to only offer the best, independent curve (`x25519`)? Wrong again, NIST says you're only TLS "compliant" if you have `secp256r1`!

  All this this leads to insane configurations, like for `google.com` where the supported named groups (a list of curves ordered by preference sent by the server) looks like this: `x25519, secp256r1`. The best overall curve followed by the weakest one from a pool that's questionable in the first place.

  So, nuTLS has no choice but to offer up `secp256r1`. However, `secp384r1` is also always offered, so that NIST-friendly clients can at least use the most secure NIST curve if they support it.
</details>

### Ciphers

nuTLS's servers will only ever present clients with extremely strong ciphers. CBC ciphers are generally a bad idea and are not implemented whatsoever in nuTLS (there are not even any CBC primitives in the crypto library). Additionally, all 128 bit ciphers are disabled in the server context. They're marked "WEAK" starting 2020 in SSLabs, and even though they are generally still considered secure, 256 bit ciphers are better still. This doesn't hurt compatiblity with clients, and all modern browsers and TLS libraries support them. To offer clients an alternative to AES-GCM 256, ChaCha20 is also offered.

Cipher Suite                                          | TLS1.3  | TLS1.2
----------------------------------------------------- | ------- | ------
AES 256 GCM SHA384 (ECDH x25519)                      | ✓       |   
CHACHA20 POLY1305 SHA256 (ECDH x25519)                | ✓       |   
DHE RSA + AES 256 GCM SHA384 (DH 4096 bits)           |         | ✓
DHE RSA + CHACHA20 POLY1305 SHA256 (DH 4096 bits)     |         | ✓
ECDHE RSA + AES 256 GCM SHA384 (ECDH secp384r1)       |         | ✓
ECDHE RSA + CHACHA20 POLY1305 SHA256 (ECDH secp384r1) |         | ✓

### Supported Clients

Running in TLS1.2 mode, nuTLS servers are compatible with virtually all modern clients, including some extended-support releases on obsolete OS (such as WinXP):

Device Support                          | TLS1.3  | TLS1.2
--------------------------------------- | ------- | ------
Android 8.1                             | ✓       | ✓  
Android 9.0                             | ✓       | ✓  
Chrome 70 / Win 10                      | ✓       | ✓  
Chrome 80 / Win 10                      | ✓       | ✓  
Firefox 73 / Win 10                     | ✓       | ✓  
Java 11.0.3                             | ✓       | ✓  
Java 12.0.1                             | ✓       | ✓  
OpenSSL 1.1.0k  R                       | ✓       | ✓  
OpenSSL 1.1.1c  R                       | ✓       | ✓  
Safari 12.1.1 / iOS 12.3.1  R           | ✓       | ✓  
Safari 12.1.2 / MacOS 10.14.6 Beta  R   | ✓       | ✓  
Android 4.4.2                           |         | ✓  
Android 7.0                             |         | ✓  
Android 8.0                             |         | ✓  
Apple ATS 9 / iOS 9  R                  |         | ✓  
BingPreview Jan 2015                    |         | ✓  
Chrome 49 / XP SP3                      |         | ✓  
Edge 13 / Win Phone 10  R               |         | ✓  
Edge 15 / Win 10  R                     |         | ✓  
Edge 16 / Win 10  R                     |         | ✓  
Edge 18 / Win 10  R                     |         | ✓  
Firefox 47 / Win 7  R                   |         | ✓  
Firefox 49 / XP SP3                     |         | ✓  
Googlebot Feb 2018                      |         | ✓  
IE 11 / Win 10  R                       |         | ✓  
IE 11 / Win 7  R                        |         | ✓  
IE 11 / Win 8.1  R                      |         | ✓  
IE 11 / Win Phone 8.1 Update  R         |         | ✓  
Java 8u161                              |         | ✓  
OpenSSL 1.0.1l  R                       |         | ✓  
OpenSSL 1.0.2s  R                       |         | ✓  
Safari 10 / iOS 10  R                   |         | ✓  
Safari 10 / OS X 10.12  R               |         | ✓  
Safari 9 / iOS 9  R                     |         | ✓  
Safari 9 / OS X 10.11  R                |         | ✓  
Yahoo Slurp Jan 2015                    |         | ✓  
YandexBot Jan 2015                      |         | ✓  
Android 5.0.0                           |         |   
Android 6.0                             |         |   
Chrome 69 / Win 7  R                    |         |   
Firefox 31.3.0 ESR / Win 7              |         |   
Firefox 62 / Win 7  R                   |         |   
IE 11 / Win Phone 8.1  R                |         |   
Safari 6 / iOS 6.0.1                    |         |   
Safari 7 / iOS 7.1  R                   |         |   
Safari 7 / OS X 10.9  R                 |         |   
Safari 8 / iOS 8.4  R                   |         |   
Safari 8 / OS X 10.10  R                |         |   

### DH Parameters

nuTLS only supports 4096 bit DH parameters. The parameters included in nutls.c are generated by OpenSSL in safe-prime mode. This also contributes to the higher "Key Exchange" score.

Really old clients might not be able to handle this (see list above).

### Forward Secrecy

ECDHE suites are preferred to enable perfect forward secrecy.

## nuTLS for Clients

nuTLS can be used for TLS1.2 and 1.3 client programs. They can optionally perform certificate validations (expiration, chain validation, CA verification) based on a root PEM bundle (see client.c as an example). Clients are a bit more flexible in terms of supported ciphers. They allow connections to servers preferring AES-GCM 128 ciphers (which is fine). CBC ciphers are not supported.

Note: Certificate chain validation is not implemented for TLS1.2 where the chain may contain ECDSA certs. That is the case for all current sites behind Cloudflare. In that case, either skip the chain validation or switch to TLS1.3. Generally, TLS1.2 should be your first choice. You may implement retries if you don't know what sites you are connecting to beforehand:

![](https://mermaid.ink/svg/eyJjb2RlIjoiZ3JhcGggVERcbiAgQVtUTFMxLjIgQ2xpZW50XSAtLT58U3VjY2Vzc3wgQihSZXNwb25zZSlcbiAgQSAtLT58RmFpbHVyZXwgQ3tFQ0RTQT99XG4gIEMgLS0-fE5vfCBEKEVycm9yKVxuICBDIC0tPnxZZXN8IEVcbiAgRVtUTFMxLjMgQ2xpZW50XSAtLT58U3VjY2Vzc3wgQlxuICBFIC0tPnxGYWlsdXJlfCBEXG4iLCJtZXJtYWlkIjp7InRoZW1lIjoiZGVmYXVsdCJ9LCJ1cGRhdGVFZGl0b3IiOmZhbHNlfQ)

ECDSA validation might be added in the future for TLS1.2.