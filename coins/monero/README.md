# monero-serai

A modern Monero transaction library intended for usage in wallets. It prides
itself on accuracy, correctness, and removing common pit falls developers may
face.

monero-serai also offers the following features:

- Featured Addresses
- A FROST-based multisig orders of magnitude more performant than Monero's

### Purpose and support

monero-serai was written for Serai, a decentralized exchange aiming to support
Monero. Despite this, monero-serai is intended to be a widely usable library,
accurate to Monero. monero-serai guarantees the functionality needed for Serai,
yet will not deprive functionality from other users.

Various legacy transaction formats are not currently implemented, yet we are
willing to add support for them. There aren't active development efforts around
them however.

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

It also won't act as a wallet, just as a transaction library. wallet2 has
several *non-transaction-level* policies, such as always attempting to use two
inputs to create transactions. These are considered out of scope to
monero-serai.
