# Ciphersuite

Ciphersuites for elliptic curves premised on ff/group.

This library, except for the not recommended Ed448 ciphersuite, was
[audited by Cypher Stack in March 2023](../../audits/Cypher Stack crypto March 2023/Audit.pdf),
culminating in commit 669d2dbffc1dafb82a09d9419ea182667115df06.

### Secp256k1/P-256

Secp256k1 and P-256 are offered via [k256](https://crates.io/crates/k256) and
[p256](https://crates.io/crates/p256), two libraries maintained by
[RustCrypto](https://github.com/RustCrypto).

Their `hash_to_F` is the
[IETF's hash to curve](https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html),
yet applied to their scalar field.

### Ed25519/Ristretto

Ed25519/Ristretto are offered via
[dalek-ff-group](https://crates.io/crates/dalek-ff-group), an ff/group wrapper
around [curve25519-dalek](https://crates.io/crates/curve25519-dalek).

Their `hash_to_F` is the wide reduction of SHA2-512, as used in
[RFC-8032](https://www.rfc-editor.org/rfc/rfc8032). This is also compliant with
the draft
[RFC-RISTRETTO](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-05.html).
The domain-separation tag is naively prefixed to the message.

### Ed448

Ed448 is offered via [minimal-ed448](https://crates.io/crates/minimal-ed448), an
explicitly not recommended, unaudited, incomplete Ed448 implementation, limited
to its prime-order subgroup.

Its `hash_to_F` is the wide reduction of SHAKE256, with a 114-byte output, as
used in [RFC-8032](https://www.rfc-editor.org/rfc/rfc8032). The
domain-separation tag is naively prefixed to the message.
