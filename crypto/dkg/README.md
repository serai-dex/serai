# Distributed Key Generation

A collection of implementations of various distributed key generation protocols.

All included protocols resolve into the provided `Threshold` types, intended to
enable their modularity. Additional utilities around these types, such as
promotion from one generator to another, are also provided.

Currently, the only included protocol is the two-round protocol from the
[FROST paper](https://eprint.iacr.org/2020/852).

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing.
