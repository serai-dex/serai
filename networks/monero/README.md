# monero-serai

A modern Monero transaction library. It provides a modern, Rust-friendly view of
the Monero protocol.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Wallet Functionality

monero-serai originally included wallet functionality. That has been moved to
monero-wallet.

### Purpose and Support

monero-serai was written for Serai, a decentralized exchange aiming to support
Monero. Despite this, monero-serai is intended to be a widely usable library,
accurate to Monero. monero-serai guarantees the functionality needed for Serai,
yet does not include any functionality specific to Serai.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators` (on by default): Derives the generators at
  compile-time so they don't need to be derived at runtime. This is recommended
  if program size doesn't need to be kept minimal.
- `multisig`: Enables the `multisig` feature for all dependencies.
