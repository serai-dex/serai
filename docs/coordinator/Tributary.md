# Tributary

A tributary is a side-chain, created for a specific multisig instance, used
as a verifiable broadcast layer.

## Transactions

### Key Gen Commitments

`DkgCommitments` is created when a processor sends the coordinator
`key_gen::ProcessorMessage::Commitments`. When all validators participating in
a multisig publish `DkgCommitments`, the coordinator sends the processor
`key_gen::CoordinatorMessage::Commitments`, excluding the processor's own
commitments.

### Key Gen Shares

`DkgShares` is created when a processor sends the coordinator
`key_gen::ProcessorMessage::Shares`. The coordinator additionally includes its
own pair of MuSig nonces, used in a signing protocol to inform Substrate of the
key's successful creation.

When all validators participating in a multisig publish `DkgShares`, the
coordinator sends the processor `key_gen::CoordinatorMessage::Shares`, excluding
the processor's own shares and the MuSig nonces.

### Key Gen Confirmation

`DkgConfirmed` is created when a processor sends the coordinator
`key_gen::ProcessorMessage::GeneratedKeyPair`. The coordinator takes the MuSig
nonces they prior associated with this DKG attempt and publishes their signature
share.

When all validators participating in the multisig publish `DkgConfirmed`, an
extrinsic calling `validator_sets::pallet::set_keys` is made to confirm the
keys.

Setting the keys on the Serai blockchain as such lets it receive `Batch`s,
provides a BFT consensus guarantee, and enables accessibility by users. While
the tributary itself could offer both the BFT consensus guarantee, and
verifiable accessibility to users, they'd both require users access the
tributary. Since Substrate must already know the resulting key, there's no value
to usage of the tributary as-such, as all desired properties are already offered
by Substrate.

Note that the keys are confirmed when Substrate emits a `KeyGen` event,
regardless of if the Tributary has the expected `DkgConfirmed` transactions.

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

When `t` validators have published `BatchPreprocess` transactions, if the
coordinator represents one of the first `t` validators to do so, a
`coordinator::ProcessorMessage::BatchPreprocesses` is sent to the processor,
excluding the processor's own preprocess.

### Batch Share

`BatchShare` is created when a processor sends the coordinator
`coordinator::ProcessorMessage::BatchShare`. The relevant `ExternalBlock`
transaction having already been included on chain follows from
`coordinator::ProcessorMessage::BatchShare` being a response to a message which
also has that precondition.

When the `t` validators who first published `BatchPreprocess` transactions have
published `BatchShare` transactions, if the coordinator represents one of the
first `t` validators to do so, a `coordinator::ProcessorMessage::BatchShares`
with the relevant shares (excluding the processor's own) is sent to the
processor.

### Sign Preprocess

`SignPreprocess` is created when a processor sends the coordinator
`sign::ProcessorMessage::Preprocess` and a `SubstrateBlock` transaction
allowing the transaction to be signed has already been included on chain.

When `t` validators have published `SignPreprocess` transactions, if the
coordinator represents one of the first `t` validators to do so, a
`sign::ProcessorMessage::Preprocesses` is sent to the processor,
excluding the processor's own preprocess.

### Sign Share

`SignShare` is created when a processor sends the coordinator
`sign::ProcessorMessage::Share`. The relevant `SubstrateBlock` transaction
having already been included on chain follows from
`sign::ProcessorMessage::Share` being a response to a message which
also has that precondition.

When the `t` validators who first published `SignPreprocess` transactions have
published `SignShare` transactions, if the coordinator represents one of the
first `t` validators to do so, a `sign::ProcessorMessage::Shares` with the
relevant shares (excluding the processor's own) is sent to the processor.

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
