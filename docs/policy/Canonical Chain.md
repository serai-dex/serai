# Canonical Chain

As Serai is a network connected to many external networks, at some point we will
likely have to ask ourselves what the canonical chain for a network is. This
document intends to establish soft, non-binding policy, in the hopes it'll guide
most discussions on the matter.

The canonical chain is the chain Serai follows and honors transactions on. Serai
does not guarantee operations availability nor integrity on any chains other
than the canonical chain. Which chain is considered canonical is dependent on
several factors.

### Finalization

Serai finalizes blocks from external networks onto itself. Once a block is
finalized, it is considered irreversible. Accordingly, the primary tenet
regarding what chain Serai will honor is the chain Serai has finalized. We can
only assume the integrity of our coins on that chain.

### Node Software

Only node software which passes a quality threshold and actively identifies as
belonging to an external network's protocol should be run. Never should a
transformative node (a node trying to create a new network from an existing one)
be run in place of a node actually for the external network. Beyond active
identification, it must have community recognition as belonging.

If the majority of a community actively identifying as the network stands behind
a hard fork, it should not be considered as a new network yet the next step of
the existing one. If a hard fork breaks Serai's integrity, it should not be
supported.

Multiple independent nodes should be run in order to reduce the likelihood of
vulnerabilities to any specific node's faults.

### Rollbacks

Over time, various networks have rolled back in response to exploits. A rollback
should undergo the same scrutiny as a hard fork. If the rollback breaks Serai's
integrity, yet someone identifying as from the project offers to restore
integrity out-of-band, integrity is considered kept so long as the offer is
followed through on.

Since a rollback would break Serai's finalization policy, a technical note on
how it could be implemented is provided.

Assume a blockchain from `0 .. 100` exists, with `100a ..= 500a` being rolled
back blocks. The new chain extends from `99` with `100b ..= 200b`. Serai would
define the canonical chain as `0 .. 100`, `100a ..= 500a`, `100b ..= 200b`, with
`100b` building off `500a`. Serai would have to perform data-availability for
`100a ..= 500a` (such as via a JSON file in-tree), and would have to modify the
processor to edit its `Eventuality`s/UTXOs at `500a` back to the state at `99`.
Any `Burn`s handled after `99` should be handled once again, if the transactions
from `100a ..= 500a` cannot simply be carried over.

### On Fault

If the canonical chain does put Serai's coins into an invalid state,
irreversibly and without amends, then the discrepancy should be amortized to all
users as feasible, yet affected operations should otherwise halt if under
permanent duress.

For example, if Serai lists a token which has a by-governance blacklist
function, and is blacklisted without appeal, Serai should destroy all associated
sriXYZ and cease operations.

If a bug, either in the chain or in Serai's own code, causes a loss of 10% of
coins (without amends), operations should halt until all outputs in system can
have their virtual amount reduced by a total amount of the loss,
proportionalized to each output. Alternatively, Serai could decrease all token
balances by 10%. All liquidity/swap operations should be halted until users are
given proper time to withdraw, if they so choose, before operations resume.
