# Distributed Key Generation - Promote

This crate implements 'promotions' for keys from the [`dkg`](https://docs.rs/dkg) crate. A promotion
takes a set of keys and maps it to a different `Ciphersuite`.

This crate was originally part of the `dkg` crate, which was
[audited by Cypher Stack in March 2023](
  https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf
), culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](
  https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06
). Any subsequent changes have not undergone auditing.
