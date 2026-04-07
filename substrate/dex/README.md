# Serai DEX Pallet

Serai is a cross-chain decentralized exchange which, critically, requires
decentralized exchange functionality in order to function. This pallet provides
the decentralized exchange functionality for the Serai protocol.

The exact functionality at this time is liquidity pools, specifically
constant-product automated market makers, following the traditional `x * y = k`
formula. The arithmetic underlying them is _not_ implemented in this crate but
rather the MIT-licensed [`serai_primitives`] library. This is intentional so
applications may integrate the underlying formulas, enabling calculating
quotes, without being subject to this crate's AGPL 3.0 license.

### Structure

Each liquidity pool in the Serai protocol is for a pair `SRI - EXT`, where
`EXT` is an external coin. This allows identifying any individual liquidity
pool solely by its external coin, which explains why
[`serai_abi::dex::address`] (the function which yields a liquidity pool's
address) has its only argument as an [`ExternalCoin`].

The liquidity pool does not store any state itself. Instead, it determines the
amount within the pool by querying its balance from the `Coins` module (the
[`CoinsInstance`] of [`serai_coins_pallet`]). When coins are added to the
liquidity pool, some designs may query the difference between the last
recognized balance and the current balance to determine the delta (requiring
storing the last recognized balance), yet Serai's implementation performs the
transfers itself to definitively identify the amount transferred as relevant to
the current operations.

Swaps from `EXT - EXT'`, where `EXT != EXT'`, are possible despite no such
liquidity pools existing. Such swaps will internally be routed as
`EXT - SRI - EXT'`, where each immediate pair does have a liquidity pool.

### Liquidity Tokens

Liquidity is fungibly represented as tokens, which may be transferred between
accounts (in order to support rotating the keys controlling it). The underlying
implementation is via [`serai_coins_pallet`], as parameterized by the
[`LiquidityTokensInstance`], ensuring the safety of the underlying arithmetic
for transfers. The interface for these tokens ([`serai_abi::dex::Call`],
[`serai_abi::dex::Event`]) is entirely implemented within this crate however.

### Audit Status

This was
[audited by Security Research Labs](/audits/substrate/Security%20Research%20Labs%20April%202026)
as of commit `30e61adb9b5318cdd2b2cf9c3f8ce6c9afef1cb0`. Any following changes
were not audited unless otherwise stated. Please read the linked report for
more information.
