# Multiexp

A multiexp implementation for ff/group implementing Straus and Pippenger. A
batch verification API is also available via the "batch" feature, which enables
secure multiexponentation batch verification given a series of values which
should sum to 0, identifying which doesn't via binary search if they don't.

This library was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/74924095e1a0f266b58181b539d9e74fa35dc37a/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit 669d2dbffc1dafb82a09d9419ea182667115df06.
