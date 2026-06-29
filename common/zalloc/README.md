# `zalloc`

A Rust allocator which zeroizes all memory on deallocation.

### Global Allocator

[`ZeroizingAlloc`] may wrap an implementation of [`GlobalAlloc`] such that on
[`GlobalAlloc::dealloc`], it first zeroizes the memory via the [`zeroize`] crate.

### Allocator

On nightly, with the `allocator` feature enabled, [`ZeroizingAlloc`] also
implements
[`Allocator`](https://doc.rust-lang.org/1.96.0/alloc/alloc/trait.Allocator.html)
and can be used for individual values with
[`Box`](https://doc.rust-lang.org/1.96.0/alloc/boxed/struct.Box.html). This is
notable for effecting zeroize even for types which don't implement
[`Zeroize`](https://docs.rs/zeroize/1.9.0/zeroize/trait.Zeroize.html).

### Safety

This assumes that as memory is being deallocated, it is without conflict to
write zeroes to the pointer corresponding to the size of the layout. For any
allocator which requires being able to inspect deallocated memory, this has
undefined behavior, with no promises made about its safety.
