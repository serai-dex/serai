# eVRF DKG

The DKG from the [eVRF paper](https://eprint.iacr.org/2024/397), extended with
Verifiable Encryption premised on the same methodology present in the eVRF
paper.

The DDH-premised VRF is used, yet the different instantiation presented in
section 6.4 premised on elliptic curve divisors. The one-round threshold DKG
presented in section 4.2 is extended, with the following changes:

- Any threshold of `t` participants may complete the DKG. This allows an
  adversary to bias the resulting key by choosing the set of participants, yet
  offers a robust protocol. The caller is able to choose between robustness and
  a lack of bias by completing the DKG with just `t` messages or by waiting for
  all `n`. If the caller does opt for robustness, the caller must ensure
  participants agree on the subset of participants who actually participated.

- Communication of shares was prior defined as simply sending the share to the
  relevant participant, with no description of the channel. Now, a pair of
  ECDHs are performed on the embedded curve occurs (between the sender and the
  recipient's public key), whose `x` coordinates are summed for a random,
  uniform value (as an eVRF would). This value is used as a mask to encrypt the
  communicated secret share, with the zero-knowledge proof proving it's
  well-formed. This removes the need for a complaint round from the protocol,
  allowing it to truly complete (with all recipients holding valid shares) in
  just one round.

For a gist of the verifiable encryption scheme, please see
https://gist.github.com/kayabaNerve/cfbde74b0660dfdf8dd55326d6ec33d7. For
security proofs and audit information, please see
[here](../../../audits/crypto/dkg/evrf).

---

This library supports being run in no-std contexts with `alloc` when the `std`
feature (on by default) is disabled. Due to the intensity of the ZK proofs,
this isn't recommended, yet may be justified when _verifying_ posted proofs are
correct.
