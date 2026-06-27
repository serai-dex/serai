# Ciphersuite

Extension traits for elliptic curves which make use of the
[`group`](https://docs.rs/group) APIs, as usable to define ciphersuites as
needed within larger protocols/contexts.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing.

This library is usable under no-`std`. The `alloc` and `std` features enable
reading from the `io::Read` trait, shimmed by `std-shims` under `alloc`.
