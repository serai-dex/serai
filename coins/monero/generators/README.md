# Monero Generators

Generators used by Monero in both its Pedersen commitments and Bulletproofs(+).
An implementation of Monero's `ge_fromfe_frombytes_vartime`, simply called
`hash_to_point` here, is included, as needed to generate generators.

This library is usable under no_std when the `alloc` feature is enabled.
