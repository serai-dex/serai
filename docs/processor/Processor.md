# Processor

The processor is a service which has an instance spawned per network. It is
responsible for several tasks, from scanning the connected network to signing
transactions with payments.

This document primarily discusses its flow with regards to the coordinator.

## Generate Key

On `key_gen::CoordinatorMessage::GenerateKey`, the processor begins a pair of
instances of the distributed key generation protocol specified in the FROST
paper.

The first instance is for a key to use on the connected network. The second
instance is for a Ristretto public key used to publish data to the Serai
blockchain. This pair of FROST DKG instances is considered a single instance of
Serai's overall key generation protocol.

The commitments for both protocols are sent to the coordinator in a single
`key_gen::ProcessorMessage::Commitments`.

## Key Gen Commitments

On `key_gen::CoordinatorMessage::Commitments`, the processor continues the
specified key generation instance. The secret shares for each fellow
participant are sent to the coordinator in a
`key_gen::ProcessorMessage::Shares`.

### Key Gen Shares

On `key_gen::CoordinatorMessage::Shares`, the processor completes the specified
key generation instance. The generated key pair is sent to the coordinator in a
`key_gen::ProcessorMessage::GeneratedKeyPair`.

## Confirm Key Pair

On `substrate::CoordinatorMessage::ConfirmKeyPair`, the processor starts using
the newly confirmed key, scanning blocks on the connected network for
transfers to it.

## Connected Network Block

When the connected network has a new block, which is considered finalized
(either due to being literally finalized or due to having a sufficient amount
of confirmations), it's scanned.

Outputs to the key of Serai's multisig are saved to the database. Outputs which
newly transfer into Serai are used to build `Batch`s for the block. The
processor then begins a threshold signature protocol with its key pair's
Ristretto key to sign the `Batch`s. The protocol's preprocess is sent to the
coordinator in a `coordinator::ProcessorMessage::BatchPreprocess`.

As a design comment, we *may* be able to sign now possible, already scheduled,
branch/leaf transactions at this point. Doing so would be giving a mutable
borrow over the scheduler to both the external network and the Serai network,
and would accordingly be unsafe. We may want to look at splitting the scheduler
in two, in order to reduce latency (TODO).

## Batch Preprocesses

On `coordinator::CoordinatorMessage::BatchPreprocesses`, the processor
continues the specified batch signing protocol, sending
`coordinator::ProcessorMessage::BatchShare` to the coordinator.

## Batch Shares

On `coordinator::CoordinatorMessage::BatchShares`, the processor
completes the specified batch signing protocol. If successful, the processor
stops signing for this batch and sends `substrate::ProcessorMessage::Update` to
the coordinator.

## Batch Re-attempt

On `coordinator::CoordinatorMessage::BatchReattempt`, the processor will create
a new instance of the batch signing protocol. The new protocol's preprocess is
sent to the coordinator in a `coordinator::ProcessorMessage::BatchPreprocess`.

## Substrate Block

On `substrate::CoordinatorMessage::SubstrateBlock`, the processor:

1) Marks all blocks, up to the external block now considered finalized by
   Serai, as having had their batches signed.
2) Adds the new outputs from newly finalized blocks to the scheduler, along
   with the necessary payments from `Burn` events on Serai.
3) Sends a `substrate::ProcessorMessage::SubstrateBlockAck`, containing the IDs
   of all plans now being signed for, to the coordinator.
4) Sends `sign::ProcessorMessage::Preprocess` for each plan now being signed
   for.

## Sign Preprocesses

On `sign::CoordinatorMessage::Preprocesses`, the processor continues the
specified transaction signing protocol, sending `sign::ProcessorMessage::Share`
to the coordinator.

## Sign Shares

On `sign::CoordinatorMessage::Shares`, the processor completes the specified
transaction signing protocol. If successful, the processor stops signing for
this transaction and publishes the signed transaction. Then,
`sign::ProcessorMessage::Completed` is sent to the coordinator, to be
broadcasted to all validators so everyone can observe the attempt completed,
producing a signed and published transaction.

## Sign Re-attempt

On `sign::CoordinatorMessage::Reattempt`, the processor will create a new
a new instance of the transaction signing protocol if it hasn't already
completed/observed completion of an instance of the signing protocol. The new
protocol's preprocess is sent to the coordinator in a
`sign::ProcessorMessage::Preprocess`.

## Sign Completed

On `sign::CoordinatorMessage::Completed`, the processor verifies the included
transaction hash actually refers to an accepted transaction which completes the
plan it was supposed to. If so, the processor stops locally signing for the
transaction, and emits `sign::ProcessorMessage::Completed` if it hasn't prior.
