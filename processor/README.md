# Processor

The Serai processor scans a specified chain, communicating with the coordinator.

### Key Generation

The coordinator will tell the processor if it's been included in managing a
coin. If so, the processor is to begin the key generation protocol, relying on
the coordinator to provided authenticated communication with the remote parties.

When the key generation protocol successfully completes, the processor is
expected to inform the coordinator so it may vote on it on the Substrate chain.
Once the key is voted in, it'll become active.

### Scanning

Sufficiently confirmed block become finalized in the eyes of the procesor.
Finalized blocks are scanned and have their outputs emitted, though not acted
on.

### Reporting

The processor reports finalized blocks to the coordinator. Once the group
acknowledges the block as finalized, they begin a threshold signing protocol
to sign the block's outputs as a `Batch`.

Once the `Batch` is signed, the processor emits an `Update` with the signed
batch. Serai includes it, definitively ordering its outputs within the context
of Serai.

### Confirmed Outputs

With the outputs' ordering, validators are able to act on them.

Actions are triggered by passing the outputs to the scheduler. The scheduler
will do one of two things:

1) Use the output
2) Accumulate it for later usage

### Burn Events

When the Serai chain issues a `Burn` event, the processor should send coins
accordingly. This is done by scheduling the payments out.

# TODO

- Items marked TODO
- Items marked TODO2, yet those only need to be done after protonet
- Test the implementors of Coin against the trait API
- Test the databases
- Test eventuality handling

- Coordinator communication

Kafka? RPC ping to them, which we don't count as 'sent' until we get a pong?
