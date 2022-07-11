# Serai

Serai is a new DEX, built from the ground up, initially planning on listing
Bitcoin, Ethereum, Monero, DAI, and USDC, offering a liquidity pool trading
experience. Funds are stored in an economically secured threshold multisig
wallet.

### Layout

- `docs` - Documentation on the Serai protocol.

- `coins` - Various coin libraries intended for usage in Serai yet also by the
  wider community. This means they will always support the functionality Serai
  needs, yet won't disadvantage other use cases when possible.

- `crypto` - A series of composable cryptographic libraries built around the
  `ff`/`group` APIs achieving a variety of tasks. These range from generic
  infrastructure, to our IETF-compliant FROST implementation, to a DLEq proof as
  needed for Bitcoin-Monero atomic swaps.

- `processor` - A generic chain processor to process data for Serai and process
  events from Serai, executing transactions as expected and needed.
