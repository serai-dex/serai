# Message Box

A simple message encryption and authentication wrapper for internal use. It's
intended to protect against a single compromised service from abusing its
networked state to gain privileges not granted to it, while also protecting
against logs, packet captures, and some degree of MITM attacks.

### Identity Management

Services are identified by two means:

1) A static string intended to be a human readable identifier. Constants should
   be defined containing these strings, enabling one-line edits and compile time
   identification that a service doesn't exist.

2) A Ristretto point, which is intended to be generated at time of deployment.
   Each service should have its private key and the public keys of all services
   it'll communicate with.

### Encryption Key Derivation

An ECDH of the Ristretto points occurs to obtain a shared key. This key is
hashed with context to create an encryption key used bidirectionally.

### Encryption

Messages are encrypted with XChaCha20.

### Sender Authentication

While XChaCha20Poly1305 would offer authentication for a minimal surcharge (16
bytes), it isn't asymmetric. Either service being compromised would allow
forging messages in either direction. While this is arguably fine, as a service
forging messages out is expected when it's compromised, and forging messages in
isn't needed if compromised, the ability to guarantee resolving the sender was
appreciated.

Accordingly, Schnorr signatures over Ristretto are used to authenticate the
sender.

### Receiver Authentication

The receiver's name is embedded into the sender's signature challenge. If
another service attempts to process the message, it'll fail to verify the
signature.
