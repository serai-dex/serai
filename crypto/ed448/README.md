# Minimal Ed448

Barebones implementation of Ed448 bound to the ff/group API, rejecting torsion
to achieve a PrimeGroup definition.

This library has not been audited. While it is complete, and decently tested,
any usage of it should be carefully considered.

constant time and no_std.
