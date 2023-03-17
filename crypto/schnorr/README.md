# Schnorr Signatures

A challenge (and therefore HRAm) agnostic Schnorr signature library. This is
intended to be used as a primitive by a variety of crates relying on Schnorr
signatures, voiding the need to constantly define a Schnorr signature struct
with associated functions.

This library provides signatures of the `R, s` form. Batch verification is
supported via the multiexp crate. Half-aggregation, as defined in
https://eprint.iacr.org/2021/350, is also supported.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/74924095e1a0f266b58181b539d9e74fa35dc37a/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit 669d2dbffc1dafb82a09d9419ea182667115df06.
