# bitcoin-serai

An application of [modular-frost](https://docs.rs/modular-frost) to Bitcoin
transactions, enabling extremely-efficient threshold multisigs.

### Relation of `ThresholdKeys` to Public Keys

The [`dkg::ThresholdKeys`] structure represents a threshold-shared signing key
with a public key a point on an elliptic curve. In contrast, Taproot represents
public keys as solely the `x` coordinates of the associated points, dropping
the parity of the `y` coordinate. This library accepts and works with
`ThresholdKeys` but for all operations, will act as a threshold-sharing of the
discrete logarithm for a point with an even `y` coordinate. This is via scaling
the secret sharing by `-1`, negating the key, as necessary for the public key
to always have an even `y` coordinate. This will happen internally and
automatically, so consumers _MUST_ be aware that keys sharing `x` coordinates
but not `y` coordinates will not be considered distinct and may possibly be
used as if one another.
