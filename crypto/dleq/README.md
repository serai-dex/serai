# Discrete Log Equality

Implementation of discrete log equality both within a group and across groups,
the latter being extremely experimental, for curves implementing the ff/group
APIs. This library has not undergone auditing.

The cross-group DLEq is the one described in
https://web.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf, augmented
with a pair of Schnorr Proof of Knowledges in order to correct for a mistake
present in the paper.
