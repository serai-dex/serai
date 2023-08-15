# Bulletproofs+

An implementation of [Bulletproofs+](https://eprint.iacr.org/2020/735.pdf).
This library follows the paper's specifications and terminology, implementing
the weighted inner product proof, the range proof, the aggregate range proof,
before finally the arithmetic circuit proof.

Additionally, a system for writing arithmetic circuits has been added. This is
completely custom. It ensures consistency between usage of variables, exposes
multiplication and a generally inefficient addition, and a few helpful gadgets.

This library is written to be curve agnostic. It can be used with secp256k1,
Ed25519, the pasta curves, or tevone.

## Status

Optimizations are possible, such as:

- Implementation of a proper vector commitment scheme
- Optimizing the neglected prover

This library uses asserts instead of `Result`. It also has extraneous asserts
which should be moved to debug, and some debug asserts which may preferable as
regular asserts.

The transcript policies of this library need to be reviewed.

Lack of comprehensive Zeroize usage needs to be reviewed as well.

Moving multiexp to IntoIter may save several notable allocations.
