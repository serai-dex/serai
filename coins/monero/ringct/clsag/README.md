# Monero CLSAG

The CLSAG linkable ring signature, as defined by the Monero protocol.

Additionally included is a FROST-inspired threshold multisignature algorithm.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `multisig`: Provides a FROST-inspired threshold multisignature algorithm for
  use.
