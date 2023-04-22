# std shims

A crate which passes through to std when the default `std` feature is enabled,
yet provides a series of shims when it isn't.

`HashSet` and `HashMap` are provided via `hashbrown`.
