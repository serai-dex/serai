# Distributed Key Generation

A crate implementing a type for keys, presumably the result of a distributed
key generation protocol, and utilities from there.

This crate used to host implementations of distributed key generation protocols
as well (hence the name). Those have been smashed into their own crates, such
as [`musig`](https://docs.rs/musig) and [`pedpop`](https://docs.rs/pedpop).

Before being smashed, this crate was [audited by Cypher Stack in March 2023](
  https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf
), culminating in commit [669d2dbffc1dafb82a09d9419ea182667115df06](
  https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06
). Any subsequent changes have not undergone auditing.
