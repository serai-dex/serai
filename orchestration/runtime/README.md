# `serai-runtime` `Containerfile`

The `Containerfile` within this folder represents the canonical way to produce
the `serai-runtime` WASM binary as used within the Substrate blockchain's
protocol. The usage of a `Containerfile` is to ensure a deterministic build
environment independent of the machine performing the build, which
`serai-runtime`'s build script attempts but is insufficient to guarantee.

It may be quite slow to execute due to running the x86-64 image, regardless of
the host architecture.

### `reproductions/`

While the `Containerfile` is the sole canonical and endorsed way to build the
`serai-runtime` WASM binary, alternative `Containerfile`s are present within
the `reproductions/` folder. These are not intended to be alternative methods
of deployment but rather supporting evidence for the integrity of the canonical
process. Their purpose is to produce the same WASM binary with different host
environments, such as while using official releases of Rust, in order to
demonstrate the canonical method's propriety.

Currently, the following reproductions are available:
- Rust Debian (official image)
- Rust Alpine (official image)

They are verified to produce an identical WASM blob in our CI but are not
guaranteed to nor endorsed as an alternative method of production.

### `bootstrap/`

To completely demonstrate the supply chain and allow full inspection of the
entire process used to build `serai-runtime`, a bootstrap from a minimal binary
seed is present in the `bootstrap/` folder. This is again not canonical nor
endorsed, but it would be if not for the practical issue of it taking several
hours.
