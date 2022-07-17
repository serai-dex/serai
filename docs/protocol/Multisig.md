# Multisig

The multisig is represented on chain by the `Multisig` contract.

### `vote(keys: Vec<Vec<u8>>)`

Lets a validator vote on a set of keys. Once all validators have voted on these
keys, it becomes the tracked set of keys for incoming funds.

The old keys are eligible to still receive transactions for a provided grace
period. This means nodes are expected to track and oraclize incoming
transactions for both sets of keys. At the end of the grace period, the old keys
are dropped from consideration, and all funds are forwarded to the new keys at
the next transaction interval for a given chain.

The old keys are expected to process outbounds until they forward their funds,
at which point the new keys are expected to process outbounds.

Unlike transactions in, which is confirmed as part of the BFT process, a 100%
vote is used here. While the BFT process would confirm that keys were generated
and enough nodes acknowledge them the wallet would be spendable from, it does
not confirm fault tolerance. If the other 33% of nodes failed to receive their
key shares somehow, the multisig which is intended to be t-of-n would instead be
t-of-t.

Accordingly, validators are allowed to vote multiple times, and the first key
set to receive the necessary votes becomes the new key set.
