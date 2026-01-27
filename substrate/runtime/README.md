# Serai Runtime

The on-chain rules for the Serai blockchain.

### Compilation

`serai-runtime` makes use of a bespoke `build.rs` to achieve the desired
configuration. This is the only supported way to build `serai-runtime` and
attempting to directly build it for the `wasm32v1-none` target will fail.

The primary accomplishment is a deterministic output, independent of the host
environment. This is not guaranteed, so the canonical build process is still
from a specific containerized host, but is intended to allow easier
reproduction and verification. To achieve this, _most_ aspects of the host's
environment (environment variables, `cargo`/`rustc` configuration, etc.) are
dropped. It is not possible to configure the WASM blob's build via traditional
methods as it is not intended to be modified in any manner. Certain
configuration values are carried however, notably any environment variables
tuning `cargo`'s networking (allowing compilation of `serai-runtime` even when
a proxy is mandated via setting `CARGO_HTTP_PROXY` and alike).

For more information about the build script, please read the documentation
comments within `build.rs`. For the canonical build process, please refer to
`orchestration/`.

### `clippy`

`cargo clippy -p serai-runtime` _will_ invoke `clippy` on the code for the WASM
blob, as configured for the compilation of the WASM blob. This is due to
`clippy` (internally) wrapping `rustc` and the build script deferring to
whichever `rustc` `cargo` resolved as _the_ `rustc` to actually use. This does
mean `clippy` invokes the build script which invokes `clippy` however, causing
the inner `clippy`'s output to be _swallowed by the build script_.

It is recommended accordingly to lint the runtime with
`cargo clippy -p serai-runtime -- -D warnings`. This will cause `clippy` to
error on any warnings, causing the build script to error, causing `cargo` to
print the output of the build script (and its `clippy` process).

### API Stubs

For architectures which aren't `wasm32v1-none`, the `serai-runtime`
functionality is effectively entirely stubbed. While certain APIs are defined
and implemented for `RuntimeApi`, they will panic as unimplemented if called.
They only exist to declare an API contract for the WASM blob.
