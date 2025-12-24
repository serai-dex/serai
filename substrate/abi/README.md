# Serai ABI

Serai's Application Binary Interface (ABI), defining the protocol underlying
the Serai blockchain. This includes the transaction, event, and block types.

This crate is published under the MIT license to ensure it is widely usable.
In contrast, Serai's runtime is published under the AGPL 3.0 license, which
is why it isn't recommended for clients to depend on
[`serai-runtime`](https:/docs.rs/serai-runtime) (which would traditionally
define the `Call` and `Event` types for a Substrate-based blockchain).

For higher-level crates, please refer to
[`serai-client-serai`](https://docs.rs/serai-client-serai)
(implementing a client for the Serai blockchain), or
[`serai-client`](https://docs.rs/serai-client)
(implementing a client for Serai as a whole).

### Relationship to Substrate

Serai's blockchain is built on top of
[Substrate](https://github.com/paritytech/polkadot-sdk). This is considered an
implementation detail. The intent with this crate is to ensure complete control
over the blockchain's definition so in the future, if desired, the entire
Substrate framework could be replaced _without_ having to replicate any APIs or
definitions from Substrate.

An immediate example of this is with how Serai defines its own call,
transaction, block, and event types. Additionally, Serai primarily uses
[Borsh](https://borsh.io) for serialization, and not
[SCALE](
  https://docs.polkadot.com/polkadot-protocol/parachain-basics/data-encoding
) (the default within the Substrate ecosystem). For more information on this
decision, please refer to
[`serai-primitives`](https://docs.rs/serai-primitives).

Despite this, the definitions should still be familiar and easy to understand
for anyone with familiarity with Ethereum and/or Substrate.

To remain usable with Substrate without writing the entire runtime from
scratch, wrapper types are defined when the `substrate` feature is enabled.
These types implement Substrate-specific APIs so an analogue for our bespoke
types may be used with existing pallets, client code from Substrate. These,
again, are considered an implementation detail and not part of the Serai
protocol's definition nor any long-term commitment.
