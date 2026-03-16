# `serai-runtime` `build.rs`

This file serves as an alternative to the infrastructure which would
traditionally be provided by
[`substrate-wasm-builder`](https://docs.rs/substrate-wasm-builder). It is not
generally configurable itself and is tailored for Serai specifically.

### Why not `substrate-wasm-builder`?

`substrate-wasm-builder` leaves what happens under the hood as opaque to the
developer. Locally defining a build script is feasible, even if it's enough
work there _should_ be a library for it. For Serai, that work should be
undertaken to ensure clarity and propriety.

`substrate-wasm-builder` has accumulated cruft over the years however and is
not sufficiently configurable to our needs. Additionally, on Alpine Linux, it'd
fail to detect `wasm32v1-none` was installed and fall back to
`wasm32-unknown-unknown`. Serai does not want to _ever_ so fallback
(`wasm32-unknown-unknown` being a legacy choice which should have been already
removed) _and_ wanted to fix such compilations. Using `wasm32v1-none` outright,
without attempting to detect if it's installed, removes any possible bugs that
would happen during detection.

`substrate-wasm-builer` also _propagated_ the host environment when building
the target. This methodology was incompatible with `cfg_aliases` as `--cfg`
values from the outer compilation would propagate to the inner compilation.
While so overloading `--cfg` may be argued faulty design by `cfg_aliases`, and
propagation of `--cfg` may be argued correct by `substrate-wasm-builder`, this
was problematic for Serai whose runtime has a transient dependency upon
`cfg_aliases`, causing the `std`-enabled outer build to propagate the `std`
feature into the inner build of the WASM (no-`std`) blob.

### What does this do?

This build script defines a build script as expected for a Substrate runtime.
It compiles the current crate to a WASM blob itself exported by the current
crate.

This build script _attempts_ to _better enable_ reproducible builds. It does
not guarantee that the output will be reproducible or that if it is
reproducible, it will be reproducible by any other environment than the exact
same operating system, toolchain, and even file hierarchy. Serai intends to
build the runtime from within a hash-pinned OCI container
(`orchestration/runtime/Containerfile`) to ensure this, defining a test suite
to verify its methodology (`tests/reproducible-runtime`) which the CI runs
(`.github/workflows/reproducible-runtime`). Despite using an OCI container to
pin an exact environment, this build script attempts to minimize how much the
environment effects the output. This is via a few methods such as not
propagating the host environment and setting build flags which intended to make
the output (more) deterministic.

This build script also applies a variety of optimizations, both to the output
itself and the time to compile, as desirable. It should be noted
`substrate-wasm-builder` applies a pass with `wasm-opt`. This used to be
somewhat required, as `wasm-opt` was invoked to reduce the functionality within
the output WASM to the desired subset of WASM (now available as
`wasm32v1-none`), but isn't necessary today. While `wasm-opt` could still be
used as a general optimization pass, Serai doesn't employ it as:

  - The included optimizations should achieve the desired performance.
  - While `wasm-opt` was being used to reduce the WASM blob's _size_, Serai
    does not mind large WASM blobs. This is as it does not employ
    _on-chain WASM blob distribution_ as projects within the Substrate
    ecosystem frequently do for upgrades.
  - It'd add an external dependency of `wasm-opt`, requiring it be bootstrapped
    in order to perform a bootstrapped build of the runtime.

### Usage

`serai-runtime` _MUST_ be built for a non-`wasm32v1-none` target. This build
script will spawn a nested `cargo build` command to build `serai-runtime` for
the `wasm32v1-none` target, with the desired configuration and options.

`cargo` will be invoked with a cleared environment, and only select variables
propagated. It will also be invoked with a _fresh_ `CARGO_HOME`. This means any
host-specific `cargo` configuration will _NOT_ be propagated. Exceptionally,
networking configuration from the host is propagated when specified as
environment variables, as it isn't expected to impact the result and may be
necessary to download dependencies.

`SERAI_RUNTIME_VENDOR` _MAY_ be specified to provide vendored sources to use,
allowing building the runtime without connecting to the internet. The vendored
sources _MUST_ be comprehensive to both the runtime itself _and_ the Rust
standard library (which will presumably require setting `RUSTC_BOOTSTRAP=1`).

The `SERAI_PROTOCOL_ID` environment variable will be propagated, if set, as
intended for the runtime to know its protocol ID. The build script does not
require it be set nor will it provide a default value if it isn't set. The
value is _RECOMMENDED_ to be set to the currently checked-out Git commit, as is
being built to create the runtime and comprehensive to the entirety of the
Serai protocol/software stack. The value of `SERAI_PROTOCOL_ID` MUST be set
consistently when performing a reproducible build.

### Caveats

This is not expected to produce reproducible builds when compiled in a
non-`release` profile. `location-detail` includes the host-formatted file path
by default, which will be dependent on the host (even with our usage of
`-Z trim-paths`). While we could set `location-detail=line,column` to omit the
file path, this would so adversely harm debugging it isn't valued when the
intent is to enable verifying _used_ builds (not under-development builds).

The included methodology is specific to WASM, meaning this build script will
not immediately work to produce a PolkaVM runtime. Support for PolkaVM could be
assumed if one instead used `substrate-wasm-builder`.
