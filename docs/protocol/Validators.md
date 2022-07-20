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
