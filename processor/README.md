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

The processor is expected to scan all sufficiently confirmed blocks from a given
coin. This will create a list of outputs, considered pending.

### Reporting

These outputs are to be placed in a `Batch`, identified by the block containing
them. Batches are provided in an `Update` to Serai, paired by an agreed upon
block number.

The processor will also produce an `Update` if there have been no batches within
the confirmation window.

### Confirmed Outputs

Once outputs have been acknowledged by Serai, they are considered confirmed.
With their confirmation, the validators are ready to create actions based on
them.

Actions are triggered by passing the outputs to the scheduler. The scheduler
will do one of two things:

1) Use the output
2) Accumulate it for later usage

### Burn Events

When the Serai chain issues a `Burn` event, the processor should send coins
accordingly. This is done by scheduling the payments out.

# Unsolved problems

- Acknowledging a sign ID as signed so we don't continue trying

monero-serai now supports `Eventuality`s. When we have a plan to attempt,
we can create an `Eventuality` and see if it matches a given TX. A signing node
just has to submit the TX hash.

Bitcoin will have the same TX hash flow, just explicitly matching against the
inputs.

- Scheduler uses exact amounts yet we need to handle fees as well

A) Schedule into a pre-fee table and adjust it post-fee
B) When we receive an output to the branch address, add back the fee to
   perceived value (post-fee to pre-fee lookup?)

- Coordinator communication

Kafka? RPC ping to them, which we don't count as 'sent' until we get a pong?

# TODO

- Dust Handling
