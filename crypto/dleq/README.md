# Discrete Log Equality

Implementation of discrete log equality both within a group and across groups,
the latter being extremely experimental, for curves implementing the ff/group
APIs. This library has not undergone auditing and the cross-group DLEq proof has
no formal proofs available.

### Cross-Group DLEq

The present cross-group DLEq is based off
[MRL-0010](https://web.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf),
which isn't computationally correct as while it proves both keys have the same
discrete-log value for the G'/H' component, yet doesn't prove a lack of a G/H
component. Accordingly, it was augmented with a pair of Schnorr Proof of
Knowledges, proving a known G'/H' component, guaranteeing a lack of a G/H
component (assuming an unknown relation between G/H and G'/H').

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

- `EfficientLinear`. This provides ring signatures in the form ((R_G, R_H), s),
  instead of (e, s), and accordingly enables a batch verification of their final
  step. It is the most performant, and also the largest, option.

- `CompromiseLinear`. This provides signatures in the form ((R_G, R_H), s) AND
  proves for 2-bits at a time. While this increases the amount of steps in
  verifying the ring signatures, which aren't batch verified, and decreases the
  amount of items batched (an operation which grows in efficiency with
  quantity), it strikes a balance between speed and size.

The following numbers are from benchmarks performed with Secp256k1/Ed25519 on a
Intel i7-118567:

| Algorithm          | Size                    | Performance       |
|--------------------|-------------------------|-------------------|
| `ClassicLinear`    | 56829 bytes (+27%)      | 157ms (0%)        |
| `ConciseLinear`    | 44607 bytes (Reference) | 156ms (Reference) |
| `EfficientLinear`  | 65145 bytes (+46%)      | 122ms (-22%)      |
| `CompromiseLinear` | 48765 bytes  (+9%)      | 137ms (-12%)      |

CompromiseLinear is the best choce by only being marginally sub-optimal
regarding size, yet still achieving most of the desired performance
improvements. That said, neither the original postulation (which had flaws) nor
any construction here has been proven nor audited. Accordingly, they are solely
experimental, and none are recommended.

All proofs are suffixed Linear in the hope a logarithmic proof makes itself
available, which would likely immediately become the most efficient option.
