# `std` shims

`std-shims` is a Rust crate with two purposes:
- Expand the functionality of `core` and `alloc`
- Polyfill functionality only available on newer versions of Rust

The goal is to make supporting no-`std` environments, and older versions of
Rust, as simple as possible. For most use cases, replacing `std::` with
`std_shims::` and adding `use std_shims::prelude::*` is sufficient to take full
advantage of `std-shims`.

### API Surface

`std-shims` only aims to have items _mutually available_ between `alloc` (with
extra dependencies) and `std` publicly exposed. Items exclusive to `std`, with
no shims available, will not be exported by `std-shims`.

### Dependencies

`HashSet` and `HashMap` are provided via `hashbrown`. Synchronization
primitives are provided via `spin` (avoiding a requirement on
`critical-section`). Sections of `std::io` are independently matched as
possible. `rustversion` is used to detect when to provide polyfills.

### Disclaimer

No guarantee of one-to-one parity is provided. The shims provided aim to be
sufficient for the average case. Issues and pull requests are _welcome_.
