# Schnorr Signatures

A challenge (and therefore HRAm) agnostic Schnorr signature library. This is
intended to be used as a primitive by a variety of crates relying on Schnorr
signatures, voiding the need to constantly define a Schnorr signature struct
with associated functions.

This library provides signatures of the `R, s` form. Batch verification is
supported via the multiexp crate. Half-aggregation, as defined in
https://eprint.iacr.org/2021/350, is also supported.

This library was
[audited by Cypher Stack in March 2023](../../audits/Cypher Stack crypto March 2023/Audit.pdf),
culminating in commit 669d2dbffc1dafb82a09d9419ea182667115df06.
