# Serai

Serai is a new DEX, built from the ground up, initially planning on listing
Bitcoin, Ethereum, DAI, and Monero, offering a liquidity-pool-based trading
experience. Funds are stored in an economically secured threshold-multisig
wallet.

[Getting Started](docs/Getting%20Started.md)

### Layout

- `audits`: Audits for various parts of Serai.

- `docs`: Documentation on the Serai protocol.

- `common`: Crates containing utilities common to a variety of areas under
  Serai, none neatly fitting under another category.

- `crypto`: A series of composable cryptographic libraries built around the
  `ff`/`group` APIs, achieving a variety of tasks. These range from generic
  infrastructure, to our IETF-compliant FROST implementation, to a DLEq proof as
  needed for Bitcoin-Monero atomic swaps.

- `coins`: Various coin libraries intended for usage in Serai yet also by the
  wider community. This means they will always support the functionality Serai
  needs, yet won't disadvantage other use cases when possible.

- `message-queue`: An ordered message server so services can talk to each other,
  even when the other is offline.

- `processor`: A generic chain processor to process data for Serai and process
  events from Serai, executing transactions as expected and needed.

- `coordinator`: A service to manage processors and communicate over a P2P
  network with other validators.

- `substrate`: Substrate crates used to instantiate the Serai network.

- `orchestration`: Dockerfiles and scripts to deploy a Serai node/test
  environment.

- `tests`: Tests for various crates. Generally, `crate/src/tests` is used, or
  `crate/tests`, yet any tests requiring crates' binaries are placed here.

### Security

Serai hosts a bug bounty program via
[Immunefi](https://immunefi.com/bounty/serai/). For in-scope critical
vulnerabilities, we will reward whitehats with up to $30,000.

Anything not in-scope should still be submitted through Immunefi, with rewards
issued at the discretion of the Immunefi program managers.

### Links

- [Twitter](https://twitter.com/SeraiDEX):         https://twitter.com/SeraiDEX
- [Mastodon](https://cryptodon.lol/@serai):        https://cryptodon.lol/@serai
- [Discord](https://discord.gg/mpEUtJR3vz):        https://discord.gg/mpEUtJR3vz
- [Matrix](https://matrix.to/#/#serai:matrix.org):
https://matrix.to/#/#serai:matrix.org
- [Immunefi](https://immunefi.com/bounty/serai/):
https://immunefi.com/bounty/serai/
