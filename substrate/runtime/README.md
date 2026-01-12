# Serai Runtime

The on-chain rules for the Serai blockchain.

### Compilation

`serai-runtime` makes use of a bespoke `build.rs` to achieve the desired
configuration. This is the only supported way to build `serai-runtime` and
attempting to directly build it for the `wasm32v1-none` target will fail.

For more information on it, please read the documentation comments within
`build.rs`.
