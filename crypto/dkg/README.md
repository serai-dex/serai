# Distributed Key Generation

A collection of implementations of various distributed key generation protocols.

All included protocols resolve into the provided `Threshold` types, intended to
enable their modularity.

Additional utilities around them, such as promotion from one generator to
another, are also provided.

Currently included is the two-round protocol from the
[FROST paper](https://eprint.iacr.org/2020/852).
