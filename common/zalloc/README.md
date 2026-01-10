# Zalloc

An allocator wrapper which zeroizes memory on deallocation.

## Overview

Zalloc provides an implementation of a zeroizing allocator that ensures sensitive data is cleared from memory when deallocated. This is crucial for security-sensitive applications.

## Features

- **Automatic Zeroization**: All memory is zeroed before deallocation
- **GlobalAlloc Support**: Can be used as a global allocator
- **Allocator API Support**: Works with Box (requires nightly)
- **Zero Runtime Overhead**: Minimal performance impact

## Usage

```rust
use zalloc::ZeroizingAlloc;
use std::alloc::System;

#[global_allocator]
static ALLOCATOR: ZeroizingAlloc<System> = ZeroizingAlloc(System);
```

## License

MIT
