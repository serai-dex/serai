# UTXO Scheduler

A scheduler of transactions for networks premised on the UTXO model.

### Design

The scheduler is designed to achieve fulfillment of all expected payments with
an `O(1)` delay (regardless of prior scheduler state), `O(log n)` time, and
`O(log(n) + n)` computational complexity.

For the time/computational complexity, we use a tree to fulfill payments.
This quickly gives us the ability to make as many outputs as necessary
(regardless of per-transaction output limits) and only has the latency of
including a chain of `O(log n)` transactions on-chain. The only computational
overhead is in creating the transactions which are branches in the tree.
Since we split off the root of the tree from a master output, the delay to start
fulfillment is the delay for the master output to re-appear on-chain.
