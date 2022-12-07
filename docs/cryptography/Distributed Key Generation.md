# Distributed Key Generation

Serai uses a modification of Pedersen's Distributed Key Generation, which is
actually Feldman's Verifiable Secret Sharing Scheme run by every participant, as
described in the FROST paper. The modification included in FROST was to include
a Schnorr Proof of Knowledge for coefficient zero, preventing rogue key attacks.
This results in a two-round protocol.

### Encryption

In order to protect the secret shares during communication, the `dkg` library
additionally sends an encryption key. These encryption keys are used in an ECDH
to derive a shared key. This key is then hashed to obtain two keys and IVs, one
for sending and one for receiving, with the given counterparty. Chacha20 is used
as the stream cipher.
