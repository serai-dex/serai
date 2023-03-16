# Multiexp

A multiexp implementation for ff/group implementing Straus and Pippenger. A
batch verification API is also available via the "batch" feature, which enables
secure multiexponentation batch verification given a series of values which
should sum to 0, identifying which doesn't via binary search if they don't.

This library was
[audited by Cypher Stack in March 2023](../../audits/Cypher Stack crypto March 2023/Audit.pdf),
culminating in commit 669d2dbffc1dafb82a09d9419ea182667115df06.
