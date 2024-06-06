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
multiple generators. In order to ensure their correctness, an extended
[CP93's Discrete Log Equality Proof](https://chaum.com/wp-content/uploads/2021/12/Wallet_Databases.pdf)
is used. The extension is simply to transcript `n` generators, instead of just
two, enabling proving for all of them at once.

Since FROST nonces are binomial, every nonce would require two DLEq proofs. To
make this more efficient, we hash their commitments to obtain a binding factor,
before doing a single DLEq proof for `d + be`, similar to how FROST calculates
its nonces (as well as MuSig's key aggregation).

As some algorithms require multiple nonces, effectively including multiple
Schnorr signatures within one signature, the library also supports providing
multiple nonces. The second component of a FROST nonce is intended to be
multiplied by a per-participant binding factor to ensure the security of FROST.
When additional nonces are used, this is actually a per-nonce per-participant
binding factor.

When multiple nonces are used, with multiple generators, we use a single DLEq
proof for all nonces, merging their challenges. This provides a proof of `1 + n`
elements instead of `2n`.

Finally, to support additive offset signing schemes (accounts, stealth
addresses, randomization), it's possible to specify a scalar offset for keys.
The public key signed for is also offset by this value. During the signing
process, the offset is explicitly transcripted. Then, the offset is added to the
participant with the lowest ID.

# Caching

modular-frost supports caching a preprocess. This is done by having all
preprocesses use a seeded RNG. Accordingly, the entire preprocess can be derived
from the RNG seed, making the cache just the seed.

Reusing preprocesses would enable a third-party to recover your private key
share. Accordingly, you MUST not reuse preprocesses. Third-party knowledge of
your preprocess would also enable their recovery of your private key share.
Accordingly, you MUST treat cached preprocesses with the same security as your
private key share.

Since a reused seed will lead to a reused preprocess, seeded RNGs are generally
frowned upon when doing multisignature operations. This isn't an issue as each
new preprocess obtains a fresh seed from the specified RNG. Assuming the
provided RNG isn't generating the same seed multiple times, the only way for
this seeded RNG to fail is if a preprocess is loaded multiple times, which was
already a failure point.
