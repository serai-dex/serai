# Distributed Key Generation

Serai uses a modification of Pedersen's Distributed Key Generation, which is
actually Feldman's Verifiable Secret Sharing Scheme run by every participant, as
described in the FROST paper. The modification included in FROST was to include
a Schnorr Proof of Knowledge for coefficient zero, preventing rogue key attacks.
This results in a two-round protocol.

### Encryption

In order to protect the secret shares during communication, the `dkg` library
establishes a public key for encryption at the start of a given protocol.
Every encrypted message (such as the secret shares) then includes a per-message
encryption key. These two keys are used in an Elliptic-curve Diffie-Hellman
handshake to derive a shared key. This shared key is then hashed to obtain a key
and IV for use in a ChaCha20 stream cipher instance, which is xor'd against a
message to encrypt it.

### Blame

Since each message has a distinct key attached, and accordingly a distinct
shared key, it's possible to reveal the shared key for a specific message
without revealing any other message's decryption keys. This is utilized when a
participant misbehaves. A participant who receives an invalid encrypted message
publishes its key, able to without concern for side effects, With the key
published, all participants can decrypt the message in order to decide blame.
