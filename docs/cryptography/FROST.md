# FROST

Serai implements [FROST](https://eprint.iacr.org/2020/852), as specified in
[draft-irtf-cfrg-frost-11](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

### Modularity

In order to support other algorithms which decompose to Schnorr, our FROST
implementation is generic, able to run any algorithm satisfying its `Algorithm`
trait. With these algorithms, there's frequently a requirement for further
transcripting than what FROST expects. Accordingly, the transcript format is
also modular so formats which aren't naive like the IETF's can be used.

### Extensions

In order to support algorithms which require their nonces be represented across
multiple generators, FROST supports providing a nonce's commitments across
multiple generators. In order to ensure their correctness,
[CP93's Discrete Log Equality Proof](https://chaum.com/wp-content/uploads/2021/12/Wallet_Databases.pdf)
is used. `2 * (n - 1)` proofs are included, since FROST nonces are binomial.
Each pair of proofs prove discrete log equality between the first pair of
commitments and each sequential pair. In the future, a single pair of DLEq
proofs, proving for all generators, may be provided.

As some algorithms require multiple nonces, effectively including multiple
Schnorr signatures within one signature, the library also supports providing
multiple nonces. The second component of a FROST nonce is intended to be
multiplied by a per-participant binding factor to ensure the security of FROST.
When additional nonces are used, this is actually a per-nonce per-participant
binding factor.

Finally, to support additive offset signing schemes (accounts, stealth
addresses, randomization), it's possible to specify a scalar offset for keys.
The public key signed for is also offset by this value. During the signing
process, the offset is explicitly transcripted. Then, the offset is divided by
`p`, the amount of participating signers, and each signer adds it to their
post-interpolation key share.
