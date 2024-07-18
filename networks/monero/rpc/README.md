# Monero RPC

Trait for an RPC connection to a Monero daemon, built around monero-serai.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
