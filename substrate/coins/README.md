# Serai Coins Pallet

`serai-coins-pallet` implements the necessary logic for coins and tokens within
the Serai protocol. The logic itself should be familiar to anyone with
experience with the [ERC-20 token standard](
  https://github.com/ethereum/ercs/blob/8358b94b5ed4009473cb4c3040d9bba60e7bb786/ERCS/erc-20.md
), as an account-based token protocol with `supply`, `balance`, and `transfer`
functions, and an event on transfer (though lacking 'approvals'). Within the
Serai runtime, it's used where other runtimes would frequently use
[`pallet-balances`](https://docs.rs/pallet-balances) or
[`pallet-assets`](https://docs.rs/pallet-assets).

### Support for Multiple Coins

The logic present within `serai-coins-pallet` generally accepts `coin: Coin` as
an argument. The pallet is intended to support tracking balances for all
statically-defined coins within the Serai protocol. Dynamic provisioning of
tokens, and on-chain metadata for tokens, is not within the scope of the Serai
protocol and is intentionally not implemented here.

### Instances

`serai-coins-pallet` defines three instances of itself.

- [`CoinsInstance`], corresponding to [`serai_abi::coins`].
- [`LiquidityTokensInstance`], which is used to track the amount of liquidity
  tokens a user has within a liquidity pool.
- [`GenesisLiquidityTokensInstance`], which is used to track the amount of
  genesis liquidity a user contributed.

While these instances are defined within `serai-coins-pallet` (and therefore
centrally-provisioned), this is for organizational purposes and to ensure all
use-cases are kept in mind when developing `serai-coins-pallet`. The instances
themselves are via Substrate's provided instancing, not only deferring the
literal implementation of instancing but also making the scheme _technically_
loosely- (not tightly-) bound.

Only the first instance, [`CoinsInstance`], implements events (specifically
[`serai_abi::coins::Event`]) It's also the intended target for
[`serai_abi::coins::Call`]. The other instances are present for
_bookkeeping purposes_ with shared logic, but are expected to provide their own
interfaces (e.g. [`serai_abi::dex`], [`serai_abi::genesis_liquidity`]). These
interfaces are expected to provide their own checks on the semantic validity of
mints, burns, transfers, and to perform any/all associated higher-level
effects, with `serai-coins-pallet` itself solely providing a sane, functional
base of common utilities.

The other instances' frontends restrict the argument of `coin: Coin` to the
subset `coin: ExternalCoin`, corresponding to a liquidity pool (as each
external coin has a single liquidity pool, `SRI-sriEXT`). This is why
`Coin::Serai` would be a nonsensical argument for these other instances, as
it'd be referring to a `SRI-SRI` liquidity pool. This isn't a strict
requirement inherited from/assumed by `serai-coins-pallet`, solely an
observable practice which demonstrates how the common core of
`serai-coins-pallet` is interpreted and presented across different uses.

For [`CoinsInstance`] specifically, as part of satisfying the definition within
[`serai_abi::coins`], the [`Pallet::burn_with_instruction`] function is
provided to burn coins with an
[`serai_abi::primitives::instructions::OutInstruction`] associated (causing a
[`serai_abi::coins::Event::BurnWithInstruction`] event to be emitted).

### Configuration

Each instance may be configured with [`AllowMint`], a `trait` which determines
if a mint should be allowed or not. This is intended to be composed with
Serai's economic security design to limit the amount of liquidity present on
the network to be proportional to the relevant validators' stake.

### Audit Status

This was
[audited by Security Research Labs](/audits/substrate/Security%20Research%20Labs%20April%202026)
as of commit `24eefa8bc50a6d17c23a6930bcf34aab1b6163d3`. Any following changes
were not audited unless otherwise stated. Please read the linked report for
more information.
