# Monero Wallet Utilities

Additional utility functions for monero-wallet.

This library is isolated as it adds a notable amount of dependencies to the
tree, and to be a subject to a distinct versioning policy. This library may
more frequently undergo breaking API changes.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Features

- Support for Monero's seed algorithm
- Support for Polyseed

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators` (on by default): Derives the generators at
  compile-time so they don't need to be derived at runtime. This is recommended
  if program size doesn't need to be kept minimal.
- `multisig`: Adds support for creation of transactions using a threshold
  multisignature wallet.
