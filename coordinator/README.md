# Coordinator

- [`tendermint`](/tributary/tendermint) is an implementation of the Tendermint
  BFT algorithm.

- [`tributary-framework`](./tributary-framework) is a micro-blockchain
  framework. Instead of a producing a blockchain daemon like the Polkadot SDK
  or Cosmos SDK primarily intend to, a tributary is solely intended to be an
  embedded asynchronous task within a larger application.

  The Serai coordinator spawns a tributary for each validator set it's
  coordinating. This allows the participating validators to communicate in a
  byzantine-fault-tolerant manner (relying on Tendermint for consensus).

- [`cosign`](./cosign) contains a library to decide which Substrate blocks
  should be cosigned and to evaluate cosigns.

- [`substrate`](./substrate) contains a library to index the Substrate
  blockchain and handle its events.

- [`tributary`](./tributary) is our utilization of the Tributary framework for
  the necessary agreement to service the Serai processor. It includes the
  `Transaction` definition and deferred execution logic.

- [`p2p`](./p2p) is our abstract P2P API to service the Coordinator.

- [`libp2p`](./p2p/libp2p) is our libp2p-backed implementation of the P2P API.

- [`src`](./src) contains the source code for the Coordinator binary itself.
