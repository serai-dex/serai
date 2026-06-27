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

### Secp256k1/P-256

Secp256k1 and P-256 are offered via [k256](https://crates.io/crates/k256) and
[p256](https://crates.io/crates/p256), two libraries maintained by
[RustCrypto](https://github.com/RustCrypto).

Please see the [`ciphersuite-kp256`](https://docs.rs/ciphersuite-kp256) crate for more info.

### Ed25519/Ristretto

Ed25519/Ristretto are offered via
[dalek-ff-group](https://crates.io/crates/dalek-ff-group), an ff/group wrapper
around [curve25519-dalek](https://crates.io/crates/curve25519-dalek).

Please see the [`dalek-ff-group`](https://docs.rs/dalek-ff-group) crate for more info.

### Ed448

Ed448 is offered via [minimal-ed448](https://crates.io/crates/minimal-ed448), an
explicitly not recommended, unaudited, incomplete Ed448 implementation, limited
to its prime-order subgroup.

Please see the [`minimal-ed448`](https://docs.rs/minimal-ed448) crate for more info.
