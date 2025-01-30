# Transaction Chaining Scheduler

A scheduler of transactions for networks premised on the UTXO model which
support transaction chaining. Transaction chaining refers to the ability to
obtain an identifier for an output within a transaction not yet signed usable
to build and sign a transaction spending it.

### Design

The scheduler is designed to achieve fulfillment of all expected payments with
an `O(1)` delay (regardless of prior scheduler state), `O(log n)` time, and
`O(log(n) + n)` computational complexity.

Due to the ability to chain transactions, we can immediately plan/sign dependent
transactions. For the time/computational complexity, we use a tree to fulfill
payments. This quickly gives us the ability to make as many outputs as necessary
(regardless of per-transaction output limits) and only has the latency of
including a chain of `O(log n)` transactions on-chain. The only computational
overhead is in creating the transactions which are branches in the tree.
