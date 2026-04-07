# Serai Primitives

`serai-primitives` represents foundational data-types and basic functionality
used within Serai's blockchain, based on
[Substrate](https://github.com/paritytech/polkadot-sdk/tree/master/substrate).

For higher-level crates, please refer to
[`serai-abi`](https://docs.rs/serai-abi) (defining the transaction, event
types), [`serai-client-serai`](https://docs.rs/serai-client-serai)
(implementing a client for the Serai blockchain), or
[`serai-client`](https://docs.rs/serai-client) (implementing a client for Serai
as a whole).

### Encoding

Serai primarily uses [`borsh`](https://borsh.io) for (de)serializing data,
though bespoke implementations are used when it makes sense to do so. In this
case, the [`borsh::BorshSerialize`](
  https://docs.rs/borsh/latest/borsh/ser/trait.BorshSerialize.html
) and
[`borsh::BorshDeserialize`](
  https://docs.rs/borsh/latest/borsh/de/trait.BorshDeserialize.html
) traits will still be defined, solely with the desired implementations instead
of derived implementations. These desired implementations are allowed to not
follow the Borsh specification for their type and may produce a serialization
for which no corresponding Borsh schema can be defined. For more information,
please read each type's definition.

In order to be used within Substrate, which makes use of
[SCALE](
  https://docs.polkadot.com/polkadot-protocol/parachain-basics/data-encoding
), the `parity_scale_codec::{Encode, Decode, DecodeWithMemTracking}` traits are
implemented (when the `scale` feature is enabled) with methods which defer to
`borsh::{BorshSerialize, BorshDeserialize}`. This ensures a consistent encoding
while offering both the desired API and the API required by Substrate. Care is
needed when implementing (especially when deriving)
[`parity_scale_codec::MaxEncodedLen`](
  https://docs.rs/crate/parity-scale-codec/3.7.5/source/src/max_encoded_len.rs#31-40
), as this property may differ between SCALE and Borsh. Notably, containers
will differ in how they encode their lengths.

The implementations for
[`borsh::BorshSerialize::serialize`](
  https://docs.rs/borsh/latest/borsh/ser/trait.BorshSerialize.html#tymethod.serialize
) will not return an error unless the writer returns an error. This allows
serializing to a
[`Vec`](https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html) to be
considered infallible, along with encoding to a
[`parity_scale_codec::Output`](
  https://docs.rs/parity-scale-codec/latest/parity_scale_codec/trait.Output.html
) (as the
[`parity_scale_codec::Output::write` method is infallible](
  https://docs.rs/parity-scale-codec/latest/parity_scale_codec/trait.Output.html#tymethod.write
)).

As for why Borsh was preferred over SCALE,

- Borsh is a more popular codec with wider adoption
- Borsh is explicitly canonical, without malleability in its encodings
- SCALE will presumably be phased out for the
  [JAM Codec](https://docs.rs/jam-codec)

### Audit Status

This was
[audited by Security Research Labs](/audits/substrate/Security%20Research%20Labs%20April%202026)
as of commit `786ba87125ca9205e02bf74f29c49d0e28040a08`. Any following changes
were not audited unless otherwise stated. Please read the linked report for
more information.
