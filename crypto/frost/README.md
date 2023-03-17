# Modular FROST

A modular implementation of FROST for any curve with a ff/group API.
Additionally, custom algorithms may be specified so any signature reducible to
Schnorr-like may be used with FROST.

A Schnorr algorithm is provided, of the form (R, s) where `s = r + cx`, which
allows specifying the challenge format. This is intended to easily allow
integrating with existing systems.

This library offers ciphersuites compatible with the
[IETF draft](https://github.com/cfrg/draft-irtf-cfrg-frost). Currently, version
11 is supported.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/74924095e1a0f266b58181b539d9e74fa35dc37a/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit 669d2dbffc1dafb82a09d9419ea182667115df06. While this
included FROST's definition of Ed448, the underlying Ed448 ciphersuite (offered
by the ciphersuite crate) was not audited, nor was the minimal-ed448 crate
implementing the curve itself.
