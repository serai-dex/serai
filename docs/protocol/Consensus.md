# Consensus

### Inherent Transactions

Inherent transactions are a feature of Substrate enabling block producers to
include transactions without overhead. This enables forming a leader protocol
for including various forms of information on chain, such as In Instruction. By
having a single node include the data, we prevent having pointless replicas on
chain.

In order to ensure the validity of the inherent transactions, the consensus
process validates them. Under Substrate, a block with inherents is checked by
all nodes, and independently accepted or rejected. Under Serai, a block with
inherents is checked by the validators, and if a BFT majority of validators
agree it's legitimate, it is, regardless of the node's perception.

### Consensus

Serai uses Tendermint to obtain consensus on its blockchain. Tendermint details
both block production and finalization, finalizing each block as it's produced.

Validators operate contextually. They are expected to know how to create
inherent transactions and actually do so, additionally verifying inherent
transactions proposed by other nodes. Verification comes from ensuring perfect
consistency with what the validator would've proposed themselves.

While Substrate prefers block production and finalization to be distinct, such
a model would allow unchecked inherent transactions to proliferate on Serai.
Since inherent transactions detail the flow of external funds in relation to
Serai, any operations on such blocks would be unsafe to a potentially fatal
degree. Accordingly, re-bundling the two to ensure the only data in the system
is that which has been fully checked was decided as the best move forward.
