# Coordinator

The coordinator is a service which communicates with all of the processors,
all of the other coordinators over a secondary P2P network, and with the Serai
node.

This document primarily details its flow with regards to the Serai node and
processor.

## New Set Event

On `validator_sets::pallet::Event::NewSet`, the coordinator spawns a tributary
for the new set. It additionally sends the processor
`key_gen::CoordinatorMessage::GenerateKey`.

## Key Generation Event

On `validator_sets::pallet::Event::KeyGen`, the coordinator sends
`substrate::CoordinatorMessage::ConfirmKeyPair` to the processor.

# Update

On `key_gen::ProcessorMessage::Update`, the coordinator publishes an unsigned
transaction containing the signed batch to the Serai blockchain.

# Sign Completed

On `sign::ProcessorMessage::Completed`, the coordinator makes a tributary
transaction containing the transaction hash the signing process was supposedly
completed with.

Due to rushing adversaries, the actual transaction completing the plan may be
distinct on-chain. These messages solely exist to coordinate the signing
process, not to determine chain state.
