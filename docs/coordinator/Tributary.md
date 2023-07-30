# Tributary

A tributary is a side-chain, created for a specific multisig instance, used
as a verifiable broadcast layer.

## Transactions

### Key Gen Commitments

`DkgCommitments` is created when a processor sends the coordinator
`key_gen::ProcessorMessage::Commitments`. When all validators participating in
a multisig publish `DkgCommitments`, the coordinator sends the processor
`key_gen::CoordinatorMessage::Commitments`.

### Key Gen Shares

`DkgShares` is created when a processor sends the coordinator
`key_gen::ProcessorMessage::Shares`. When all validators participating in
a multisig publish `DkgShares`, the coordinator sends the processor
`key_gen::CoordinatorMessage::Shares`.

### External Block

When *TODO*, a `ExternalBlock` transaction is provided. This is used to have
the group acknowledge and synchronize around the block, without the overhead of
voting in its acknowledgment.

When a `ExternalBlock` transaction is included, participants are allowed to
publish transactions to produce a threshold signature for the block's `Batch`.

### Substrate Block

`SubstrateBlock` is provided when the processor sends the coordinator
`substrate::ProcessorMessage::SubstrateBlockAck`.

When a `SubstrateBlock` transaction is included, participants are allowed to
publish transactions for the signing protocols it causes.

### Batch Preprocess

`BatchPreprocess` is created when a processor sends the coordinator
`coordinator::ProcessorMessage::BatchPreprocess` and an `ExternalBlock`
transaction allowing the batch to be signed has already been included on chain.

When `t` validators have published `BatchPreprocess` transactions, a
`coordinator::ProcessorMessage::BatchPreprocesses` is sent to the processor.

### Batch Share

`BatchShare` is created when a processor sends the coordinator
`coordinator::ProcessorMessage::BatchShare`. The relevant `ExternalBlock`
transaction having already been included on chain follows from
`coordinator::ProcessorMessage::BatchShare` being a response to a message which
also has that precondition.

When the `t` validators who first published `BatchPreprocess` transactions have
published `BatchShare` transactions, a
`coordinator::ProcessorMessage::BatchShares` with the relevant shares is sent
to the processor.

### Sign Preprocess

`SignPreprocess` is created when a processor sends the coordinator
`sign::ProcessorMessage::Preprocess` and a `SubstrateBlock` transaction
allowing the transaction to be signed has already been included on chain.

When `t` validators have published `SignPreprocess` transactions, a
`sign::ProcessorMessage::Preprocesses` is sent to the processor.

### Sign Share

`SignShare` is created when a processor sends the coordinator
`sign::ProcessorMessage::Share`. The relevant `SubstrateBlock` transaction
having already been included on chain follows from
`sign::ProcessorMessage::Share` being a response to a message which
also has that precondition.

When the `t` validators who first published `SignPreprocess` transactions have
published `SignShare` transactions, a `sign::ProcessorMessage::Shares` with the
relevant shares is sent to the processor.

### Sign Completed

`SignCompleted` is created when a processor sends the coordinator
`sign::ProcessorMessage::Completed`. As soon as 34% of validators send
`Completed`, the signing protocol is no longer further attempted.

## Re-attempts

Key generation protocols may fail if a validator is malicious. Signing
protocols, whether batch or transaction, may fail if a validator goes offline or
takes too long to respond. Accordingly, the tributary will schedule re-attempts.
These are communicated with `key_gen::CoordinatorMessage::GenerateKey`,
`coordinator::CoordinatorMessage::BatchReattempt`, and
`sign::CoordinatorMessage::Reattempt`.

TODO: Document the re-attempt scheduling logic.
