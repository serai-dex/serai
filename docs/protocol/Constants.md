# Constants

### Types

These are the list of types used to represent various properties within the
protocol.

| Alias                   | Shorthand | Type    |
|-------------------------|-----------|---------|
| Amount                  | Amount    | u64     |
| Curve                   | Curve     | u16     |
| Coin                    | Coin      | u32     |
| Global Validator Set ID | GVSID     | u32     |
| Validator Set Index     | VS        | u8      |
| Key                     | Key       | Vec<u8> |

### Curves

Integer IDs for various curves. It should be noted some curves may be the same,
yet have distinct IDs due to having different basepoints, and accordingly
different keys. For such cases, the processor is expected to create one secret
per curve, and then use DLEq proofs to port keys to other basepoints as needed.

| Curve     | ID |
|-----------|----|
| Secp256k1 | 0  |
| Ed25519   | 1  |

### Networks

Every network connected to Serai operates over a specific curve. While the
processor generates keys for curves, these keys are bound to specific networks
via an additive offset created by hashing the network's name (among other
things). The network's key is used for all coins on that network.

Networks are not acknowledged by the Serai network, solely by the processor.

| Network  | Curve |
|----------|-------|
| Bitcoin  | 0     |
| Ethereum | 0     |
| Monero   | 1     |

### Coins

Coins exist over a network and have a distinct integer ID.

| Coin     | Network  | ID |
|----------|----------|----|
| Bitcoin  | Bitcoin  | 0  |
| Ethereum | Ethereum | 1  |
| USDC     | Ethereum | 2  |
| DAI      | Ethereum | 3  |
| Monero   | Monero   | 4  |
