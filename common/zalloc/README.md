# `zalloc`

A Rust allocator which zeroizes all memory on deallocation.

### Global Allocator

[`ZeroizingAlloc`] may wrap an implementation of [`GlobalAlloc`] such that on
[`GlobalAlloc::dealloc`], it first zeroizes the memory via the [`zeroize`] crate.

### Allocator

[`ZeroizingAlloc`] implements
[`Allocator`](https://doc.rust-lang.org/alloc/alloc/trait.Allocator.html)
and can be used for individual values with
[`Box`](https://doc.rust-lang.org/alloc/boxed/struct.Box.html). This is
notable for effecting zeroization even for types which don't implement
[`Zeroize`](https://docs.rs/zeroize/1.9.0/zeroize/trait.Zeroize.html)
_assuming in-place construction_.

### Safety

This assumes that as memory is being deallocated, it is without conflict to
write zeroes to the pointer corresponding to the size of the layout. For any
allocator which requires being able to inspect deallocated memory, this has
undefined behavior, with no promises made about its safety.
