# Mini Serai

A miniature version of the Serai stack, intended to demonstrate a lack of
system-wide race conditions in the officially stated flows.

### Why

When working on multiple multisigs, a race condition was noted. Originally, the
documentation stated that the activation block of the new multisig would be the
block after the next `Batch`'s block. This introduced a race condition, where
since multiple `Batch`s can be signed at the same time, multiple `Batch`s can
exist in the mempool at the same time. This could cause `Batch`s [1, 2] to
exist in the mempool, 1 to be published (causing 2 to be the activation block of
the new multisig), yet then the already signed 2 to be published (despite
no longer being accurate as it only had events for a subset of keys).

This effort initially modeled and tested this single race condition, yet aims to
grow to the entire system. Then we just have to prove the actual Serai stack's
flow reduces to the miniature flow modeled here. While further efforts are
needed to prove Serai's implementation of the flow is itself free of race
conditions, this is a layer of defense over the theory.

### How

[loom](https://docs.rs/loom) is a library which will execute a block of code
with every possible combination of orders in order to test results aren't
invalidated by order of execution.
