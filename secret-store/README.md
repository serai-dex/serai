# Secret Store

Serai's Secret Store serves as the environment for [`serai-env`](./env). In
doing so, it's required to host both environment variables representing
standard configuration options _and_ sensitive secrets, hence being designated
as a Secret Store.

### Usage

`serai_env::var` exists with an API approximate to `std::env::var`, yet
yielding variables from the Serai Secret Store. That is the sole
intended/supported way to interact with the Secret Store.

Services which receive secrets must support accepting connections from the
Secret Store via TCP on port 59119. The Secret Store uses a connection timeout
of five seconds (by default) which is configurable via the `CONNECTION_TIMEOUT`
environment variable (specified in milliseconds).

The host names (or IPs) for each service may be declared as follows:

- `MESSAGE_QUEUE={hostname}`
- `PROCESSOR_{NETWORK}={hostname}`
- `COORDINATOR={hostname}`
- `SERAI_NODE={hostname}`

The Secret Store accepts a single argument on boot for the path to a file
containing the (32-byte, hex-encoded) entropy. This is expanded into the full
tree of expected secrets for Serai's services, allowing only storing the root
entropy itself.

All other environment variables are proxied from the Secret Store's environment
with the following schema to designate which service to proxy to:

- `MESSAGE_QUEUE_{NAME}={VALUE}`
- `PROCESSOR_{NETWORK}_{NAME}={VALUE}`
- `COORDINATOR_{NAME}={VALUE}`
- `SERAI_NODE_{NAME}={VALUE}`

### Operation

Every minute, the Secret Store will iterate over the services it's aware of,
try and connect to each, before beginning distribution of their secrets if it
can successfully connect. While a loop per minute is inefficient and perhaps
awkward, it avoids having to accept connections (allowing the Secret Store's
container to simply reject all incoming connections).

A single message from the connected-to service is expected, containing a
Ristretto point. The Secret Store will sample its own scalar for an Elliptic
Curve Diffie-Hellman, hashing the Diffie-Hellman with `Blake2b-256` before
using it as the seed for a `ChaCha20` stream the message is `XOR`'d with.

The response is the Secret Store's commitment to their sampled scalar, so the
recipient may also calculate the Diffie-Hellman, before the encrypted
concatenation of each `"{NAME}"="{VALUE}"` for all variables/secrets. The
variables/secrets themselves are required to not have `"` within them and no
escape sequences are defined.

The security of the encryption is premised on how the shared secret is
ephemerally sampled and never reused (preventing needing to use a IV/nonce).
The scheme also isn't authenticated, as both services ephemerally sample keys
with no root of trust. This is intentional due to the Chicken and Egg problem
which would otherwise occur, needing a secret to authorize the request for
secrets.

To ensure secrets are only delivered to the intended recipient, the host (or
containerization solution) is trusted such that when the Secret Store dials a
recipient (via its hostname), it successfully does so without an active
Man-In-The-Middle (though eavesdroppers are allowed due to the use of
  encryption).

### Implementation

The implementation is written with minimal dependencies, such as `zeroize`,
`blake2`, and `curve25519-dalek`, with entirely blocking IO. This is to
minimize the Secret Store's complexity and surface area.

For hex encoding/decoding, `base16ct` isn't used. Instead, the non-branching
validation of hex characters from
[core-json](https://github.com/core-json/core-json) has been vendored. With
knowledge the hex characters are valid, decoding is trivial, with
[`core::hint::black_box`](
  https://doc.rust-lang.org/1.95.0/core/hint/fn.black_box.html
) intended as an optimization barrier (avoiding a direct dependency on
[`subtle`](https://docs.rs/subtle), though acknowledging
`core::hint::black_box` isn't guaranteed as such a barrier and is solely
offered on a best-effort basis).
