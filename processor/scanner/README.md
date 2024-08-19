# Scanner

A scanner of arbitrary blockchains for Serai.

This scanner has two distinct roles:

1) Scanning blocks for received outputs contained within them
2) Scanning blocks for the completion of eventualities

While these can be optimized into a single structure, they are written as two
distinct structures (with the associated overhead) for clarity and simplicity
reasons.
