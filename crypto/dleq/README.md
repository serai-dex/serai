# Discrete Log Equality

Implementation of discrete log equality proofs for curves implementing
`ff`/`group`.

There is also a highly experimental cross-group DLEq proof, under
the `experimental` feature, which has no formal proofs available yet is
available here regardless.

This library, except for the `experimental` feature, was
[audited by Cypher Stack in March 2023](https://github.com/serai-dex/serai/raw/e1bb2c191b7123fd260d008e31656d090d559d21/audits/Cypher%20Stack%20crypto%20March%202023/Audit.pdf),
culminating in commit
[669d2dbffc1dafb82a09d9419ea182667115df06](https://github.com/serai-dex/serai/tree/669d2dbffc1dafb82a09d9419ea182667115df06).
Any subsequent changes have not undergone auditing.

### Cross-Group DLEq

The present cross-group DLEq is based off
[MRL-0010](https://web.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf),
which isn't computationally correct as while it proves both keys have the same
discrete logarithm for their `G'`/`H'` component, it doesn't prove a lack of a
`G`/`H` component. Accordingly, it was augmented with a pair of Schnorr Proof of
Knowledges, proving a known `G'`/`H'` component, guaranteeing a lack of a
`G`/`H` component (assuming an unknown relation between `G`/`H` and `G'`/`H'`).

The challenges for the ring signatures were also merged, removing one-element
from each bit's proof with only a slight reduction to challenge security (as
instead of being uniform over each scalar field, they're uniform over the
mutual bit capacity of each scalar field). This reduction is identical to the
one applied to the proved-for scalar, and accordingly should not reduce overall
security. It does create a lack of domain separation, yet that shouldn't be an
issue.

The following variants are available:

- `ClassicLinear`. This is only for reference purposes, being the above
  described proof, with no further optimizations.

- `ConciseLinear`. This proves for 2 bits at a time, not increasing the
  signature size for both bits yet decreasing the amount of
  commitments/challenges in total.

- `EfficientLinear`. This provides ring signatures in the form
  `((R_G, R_H), s)`, instead of `(e, s)`, and accordingly enables a batch
  verification of their final step. It is the most performant, and also the
  largest, option.

- `CompromiseLinear`. This provides signatures in the form `((R_G, R_H), s)` AND
  proves for 2-bits at a time. While this increases the amount of steps in
  verifying the ring signatures, which aren't batch verified, and decreases the
  amount of items batched (an operation which grows in efficiency with
  quantity), it strikes a balance between speed and size.

The following numbers are from benchmarks performed with k256/curve25519_dalek
on a Intel i7-118567:

| Algorithm          | Size                    | Verification Time |
|--------------------|-------------------------|-------------------|
| `ClassicLinear`    | 56829 bytes (+27%)      | 157ms (0%)        |
| `ConciseLinear`    | 44607 bytes (Reference) | 156ms (Reference) |
| `EfficientLinear`  | 65145 bytes (+46%)      | 122ms (-22%)      |
| `CompromiseLinear` | 48765 bytes  (+9%)      | 137ms (-12%)      |

`CompromiseLinear` is the best choice by only being marginally sub-optimal
regarding size, yet still achieving most of the desired performance
improvements. That said, neither the original postulation (which had flaws) nor
any construction here has been proven nor audited. Accordingly, they are solely
experimental, and none are recommended.

All proofs are suffixed "Linear" in the hope a logarithmic proof makes itself
available, which would likely immediately become the most efficient option.
