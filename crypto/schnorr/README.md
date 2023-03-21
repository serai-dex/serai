# Schnorr Signatures

A challenge (and therefore HRAm) agnostic Schnorr signature library. This is
intended to be used as a primitive by a variety of crates relying on Schnorr
signatures, voiding the need to constantly define a Schnorr signature struct
with associated functions.

This library provides signatures of the `R, s` form. Batch verification is
supported via the multiexp crate. Half-aggregation, as defined in
<https://eprint.iacr.org/2021/350>, is also supported.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing.
