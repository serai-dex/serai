# Register (message)

`Register` messages mark the signer as a valid target to become a validator. They include another public key, who must also sign, of who is the manager for the validator in question.

# Stake (message)

`Stake` specifies a validator, or validator candidate, and delegates the specified amount to them. Initially, only the manager of a validator may stake to them. The stake amount must be a non-zero multiple of 1m $SRI. This is due to multisig key shares being without weights, requiring validators to be equal accordingly to ensure security. Each 1m $SRI causes a new share of the group key to be assigned.

# Resign (message)

`Resign` specifies a validator, or validator candidate, and initiates their removal. For an active validator, they will be removed at the next churn, returning their bond to the validator's manager. For a non-active validator, their bond is immediately returned.

## Rationale for the separation of Register and Stake

Ideally, a DPoS system will eventually be possible where stake takes a variadic amount. Once the stake value hits 1m, the validator is considered for active inclusion. If the stake value hits a new multiple of 1m, a new key share would be assigned. Any excess stake amount would be added to a queue and when someone else unstakes, this queue will shift in. If there is insufficient excess stake, the node would lose a key share/inclusion in validation entirely. This is not being considered for the initial release, leaving out an `Unstake` message and instead routing handling though `Resign`.

# Oraclization (message)

`Oraclization` messages are published by the current block producer and communicate an external event being communicated to the native chain. This is presumably some other cryptocurrency, such as BTC, being sent to the multisig wallet, triggering a privileged call enabling relevant actions.

# Report (message)

`Report` reports a validator for malicious or invalid behavior. This may be publishing a false `Oraclization` or failing to participate as expected. These apply a penalty to the validator's assigned rewards, which is distinct from the bond which must be kept as a multiple of 1m. If the amount deducted exceeds their assigned rewards, they are scheduled for removal with an appropriately reduced bond.

# Consensus

Consensus is a modified Aura implementation with the following notes:

- Stateful nodes exist in two forms. Contextless and contextual.
- Context is inserted by external programs which are run under the same umbrella as the node and trusted.
- Contextless nodes do not perform verification beyond technical validity on `Oraclization` and `Report`.
- Contextual nodes do perform verification on `Oraclization` and `Report` and will reject transactions which do not represent the actual context.
- If a block is finalized under Aura, contextual checks are always stated to be passing, even if the local context conflicts with it.

Since validators will not accept a block which breaks context, it will never be finalized, bypassing the contextual checks. If validators do finalize a block which seemingly breaks context, the majority of validators are saying it doesn't, signifying a locally invalid context state (perhaps simply one which is behind). By disabling contextual checks accordingly, nodes can still keep up to date with the chain and validate/participate in other contextual areas (assuming only one local contextual area is invalid).

By moving context based checks into consensus itself, we allow transforming the `Oraclization` and `Report` messages into a leader protocol. Instead of every validator publishing their own message and waiting for the chain's implementation to note 66% of the weight agrees on the duplicated messages, the validators agreeing on the block, which already happens under BFT consensus, ensures message accuracy.

Aura may be further optimizable by moving to either BLS or FROST signatures. BLS is easy to work with yet has a significance performance overhead. Considering we already have FROST, it may be ideal to use, yet it is a 2-round protocol which exponentially scales for key generation. While GRANDPA, an alternative consensus protocol, is 2-round and therefore could be seamlessly extended with FROST, it's not used here as it finalizes multiple blocks at a time. Given the contextual validity checks, it's simplest to finalize each block on their own to prevent malicious/improper chains from growing too large.

If the complexity challenge can be overcame, BABE's VRF selecting a block producer should be used to limit DoS attacks. The main issue is that BABE is traditionally partnered with GRANDPA and represents a more complex system than Aura. Further research is needed here.
