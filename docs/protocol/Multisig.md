# Multisig

Multisigs are confirmed on-chain by the `Multisig` contract. While the processor
does create the multisig, and sign for it, making it irrelevant to the chain,
confirming it on-chain solves the question of if the multisig was successfully
created or not. If each processor simply asked all other processors for
confirmation, votes lost to the network would create an inconsistent view. This
is a form of the Byzantine Generals Problem, which can be resolved by placing
votes within a BFT system.

Confirmation requires all participants confirm the new set of keys. While this
isn't BFT, despite the voting process being BFT, it avoids the scenario where
only t (where t is the BFT threshold, as used in the t-of-n multisig)
successfully generated shares, actually creating a t-of-t multisig in practice,
which is not BFT. This does mean a single node can delay a churn, which is
expected to be handled via a combination of slashing, and if necessary, removal.

Validators are allowed to vote multiple times across sets of keys, with the
first set to be confirmed becoming the set of keys for that validator set. These
keys remain valid for the validator set until it is changed. If a validator set
remains consistent despite the global validator set updating, their keys carry.
If a validator set adds a new member, and then loses them, their historical keys
are not reused.

Once new keys are confirmed for a given validator set, they become tracked and
the recommended set of keys for incoming funds. The old keys are still eligible
to receive funds for a provided grace period, requiring the current validator
set to track both sets of keys. The old keys are also still used to handle all
outgoing payments as well, until the end of the grace period, at which point
they're no longer eligible to receive funds and they forward all of their funds
to the new set of keys.

### `vote(keys: Vec<Vec<u8>>)`

Lets a validator vote on a set of keys for their validator set.
