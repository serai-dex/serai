# Multiexp

A multiexp implementation for ff/group implementing Straus and Pippenger. A
batch verification API is also available via the "batch" feature, which enables
secure multiexponentiation batch verification given a series of values which
should sum to the identity, identifying which doesn't via binary search if they
don't.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing.

This library is usable under no_std, via alloc, when the default features are
disabled.
