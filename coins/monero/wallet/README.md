# Monero Wallet

Wallet functionality for the Monero protocol, built around monero-serai. This
library prides itself on resolving common pit falls developers may face.

monero-wallet also offers a FROST-inspired multisignature protocol orders of
magnitude more performant than Monero's own.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

### Features

- Scanning Monero transactions
- Sending Monero transactions
- Sending Monero transactions with a FROST-inspired threshold multisignature
  protocol, orders of magnitude more performant than Monero's own

### Caveats

This library DOES attempt to do the following:

- Create on-chain transactions identical to how wallet2 would (unless told not
  to)
- Not be detectable as monero-serai when scanning outputs
- Not reveal spent outputs to the connected RPC node

This library DOES NOT attempt to do the following:

- Have identical RPC behavior when creating transactions
- Be a wallet

This means that monero-serai shouldn't be fingerprintable on-chain. It also
shouldn't be fingerprintable if a targeted attack occurs to detect if the
receiving wallet is monero-serai or wallet2. It also should be generally safe
for usage with remote nodes.

It won't hide from remote nodes it's monero-serai however, potentially
allowing a remote node to profile you. The implications of this are left to the
user to consider.

It also won't act as a wallet, just as a wallet functionality library. wallet2
has several *non-transaction-level* policies, such as always attempting to use
two inputs to create transactions. These are considered out of scope to
monero-serai.

Finally, this library only supports producing transactions with CLSAG
signatures. That means this library cannot spend non-RingCT outputs.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators` (on by default): Derives the generators at
  compile-time so they don't need to be derived at runtime. This is recommended
  if program size doesn't need to be kept minimal.
- `multisig`: Adds support for creation of transactions using a threshold
  multisignature wallet.
