# std shims

A crate which passes through to std when the default `std` feature is enabled,
yet provides a series of shims when it isn't.

No guarantee of one-to-one parity is provided. The shims provided aim to be sufficient for the
average case.

`HashSet` and `HashMap` are provided via `hashbrown`. Synchronization primitives are provided via
`spin` (avoiding a requirement on `critical-section`).
types are not guaranteed to be
