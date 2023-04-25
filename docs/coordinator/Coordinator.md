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

## Generated Key Pair

On `key_gen::ProcessorMessage::GeneratedKeyPair`, a
`validator_sets::pallet::vote` transaction is made to vote in the new key.

The Serai blockchain needs to know the key pair in order for it to be able to
publish `Batch`s. Additionally, having the Serai blockchain confirm the keys
provides a BFT consensus guarantee. While the tributary itself could also offer
a BFT consensus guarantee, there's no point when we'd then get BFT consensus
on the Serai blockchain anyways.

## Key Generation Event

On `validator_sets::pallet::Event::KeyGen`, the coordinator sends
`substrate::CoordinatorMessage::ConfirmKeyPair` to the processor.

# Update

On `key_gen::ProcessorMessage::Update`, the coordinator publishes an unsigned
transaction containing the signed batch to the Serai blockchain.

# Sign Completed

On `sign::ProcessorMessage::Completed`, the coordinator broadcasts the
contained information to all validators.
