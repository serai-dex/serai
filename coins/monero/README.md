# monero-serai

A modern Monero transaction library intended for usage in wallets. It prides
itself on accuracy, correctness, and removing common pit falls developers may
face.

monero-serai contains safety features, such as first-class acknowledgement of
the burning bug, yet also a high level API around creating transactions.
monero-serai also offers a FROST-based multisig, which is orders of magnitude
more performant than Monero's.

monero-serai was written for Serai, a decentralized exchange aiming to support
Monero. Despite this, monero-serai is intended to be a widely usable library,
accurate to Monero. monero-serai guarantees the functionality needed for Serai,
yet will not deprive functionality from other users, and may potentially leave
Serai's umbrella at some point.

Various legacy transaction formats are not currently implemented, yet
monero-serai is still increasing its support for various transaction types.
