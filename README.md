# Serai

Serai is a new DEX, built from the ground up, initially planning on listing
Bitcoin, Ethereum, DAI, and Monero, offering a liquidity-pool-based trading
experience. Funds are stored in an economically secured threshold-multisig
wallet.

[Contributing](CONTRIBUTING.md)

### Layout

- `audits`: Audits and security proofs for various parts of Serai.

- `spec`: The specification of the Serai protocol, both internally and as
  networked. This folder is lacking and is still being expanded on.

- `docs`: User-facing documentation on the Serai protocol. This folder is
  outlined yet needs an owner to work through it.

- `common`: Crates containing utilities common to a variety of areas under
  Serai, none neatly fitting under another category.

- `crypto`: A series of composable cryptographic libraries built around the
  `ff`/`group` APIs, achieving a variety of tasks. These range from generic
  libraries for elliptic curve cryptography to our IETF-compliant FROST
  implementation.

- `networks`: Various libraries intended for usage in Serai yet also by the
  wider community. This means they will always support the functionality Serai
  needs, yet won't disadvantage other use-cases when possible.

- `message-queue`: An ordered message queue so services can send messages to
  each other, even when the other is offline. This ensures one service's
  downtime doesn't propagate to another service's downtime, while also
  providing a layer of isolation between services.

- `processor`: A service to index a blockchain, maintain the state for received
   coins, and schedule/sign transactions.

- `coordinator`: A service to oversee the processors and communicate over a P2P
  network with other validators.

- `substrate`: The consensus rules for the Serai blockchain, and the
   implementation of the node itself, built around the
   [Substrate framework](
     https://github.com/paritytech/polkadot-sdk/tree/master/substrate
   ).

- `orchestration`: A binary to declare and spawn OCI containers for Serai's
  infrastructure.

- `tests`: E2E tests for Serai's services, along with test utilities.

- `patches`: Patches for our supply-chain to minimize dependencies and ensure
  a tighter surface.

### Links

- [Website](https://serai.exchange/): https://serai.exchange/
- [Immunefi (Bug Bounty Program)](https://immunefi.com/bounty/serai/): https://immunefi.com/bounty/serai/
- [Twitter](https://twitter.com/SeraiDEX): https://twitter.com/SeraiDEX
- [Discord](https://discord.gg/mpEUtJR3vz): https://discord.gg/mpEUtJR3vz
- [Matrix](https://matrix.to/#/#serai:matrix.org): https://matrix.to/#/#serai:matrix.org
- [Reddit](https://www.reddit.com/r/SeraiDEX/): https://www.reddit.com/r/SeraiDEX/
- [Telegram](https://t.me/SeraiDEX): https://t.me/SeraiDEX
