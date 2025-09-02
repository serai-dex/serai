# Serai Runtime

The on-chain rules for the Serai blockchain.

### Compilation

If compilation fails due to `borsh`, this is likely due to attempting to
compile to WASM binary (`no-std`) while `borsh` believes it's being compiled in
a `std` context. Serai uses a patched [`substrate-wasm-builder`](
  https://github.com/serai-dex/serai/tree/develop/polkadot-sdk/substrate/utils/wasm-builder
) which clears the `CARGO_FEATURE_STD` environment variable to prevent this,
yet `target/` directories may be contaminated if a build ever occurs without
the patched `substrate-wasm-builder`. Please attempt a clean build to resolve
the error.
