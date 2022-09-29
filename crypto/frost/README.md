# Modular FROST

A modular implementation of FROST for any curve with a ff/group API.
Additionally, custom algorithms may be specified so any signature reducible to
Schnorr-like may be used with FROST.

A Schnorr algorithm is provided, of the form (R, s) where `s = r + cx`, which
allows specifying the challenge format. This is intended to easily allow
integrating with existing systems.

This library offers ciphersuites compatible with the
[IETF draft](https://github.com/cfrg/draft-irtf-cfrg-frost). Currently, version
10 is supported.
