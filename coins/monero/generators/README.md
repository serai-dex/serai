# Monero Generators

Generators used by Monero in both its Pedersen commitments and Bulletproofs(+).
An implementation of Monero's `hash_to_ec` is included, as needed to generate
the generators.

This library is usable under no-std when the `std` feature (on by default) is
disabled.
