# Serai

Serai is a decentralization execution layer whose validators form multisig
wallets for various connected networks, offering secure decentralized custody of
foreign assets to applications built on it.

Serai is exemplified by Serai DEX, an automated-market-maker (AMM) decentralized
exchange, allowing swapping BTC, ETH, USDC, DAI, and XMR. It is the premier
application of Serai.

### Substrate

Serai is based on [Substrate](https://docs.substrate.io), a blockchain framework
offering a robust infrastructure.

### Smart Contracts

Serai offers WASM-based smart contracts. All applications are built over these
contracts, enabling composable interactions within a mutual layer. These
contracts are primarily written in [ink!](https://ink.substrate.io/), a
framework for building contracts in Rust.

Initially, smart contract deployment will not be enabled. Solely Serai DEX will
be available, due to the variety of economic considerations around securing the
multisig. Serai may expand in the future with more explicitly added
applications, each with tailored economic models, or may enable arbitrary
contract deployment. At this time, we solely plan for Serai DEX's availabiliy.

### Application Calls

Applications, such as Serai DEX, may be called via calling their relevant smart
contracts. At a low level, this is done via specifying the address of the
contract being interacted with, along with SCALE-encoded calldata.
