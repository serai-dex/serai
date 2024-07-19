# Modular FROST

A modular implementation of FROST for any curve with a ff/group API.
Additionally, custom algorithms may be specified so any signature reducible to
Schnorr-like may be used with FROST.

A Schnorr algorithm is provided, of the form (R, s) where `s = r + cx`, which
allows specifying the challenge format. This is intended to easily allow
integrating with existing systems.

This library offers ciphersuites compatible with the
[IETF draft](https://github.com/cfrg/draft-irtf-cfrg-frost). Currently, version
15 is supported.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing. While this audit included
FROST's definition of Ed448, the underlying Ed448 ciphersuite (offered by the
ciphersuite crate) was not audited, nor was the minimal-ed448 crate implementing
the curve itself.
