# Constants

### Types

These are the list of types used to represent various properties within the
protocol.

| Alias                  | Type                                         |
|------------------------|----------------------------------------------|
| SeraiAddress           | sr25519::Public (unchecked [u8; 32] wrapper) |
| Amount                 | u64                                          |
| Coin                   | u32                                          |
| Session                | u32                                          |
| Validator Set Index    | u16                                          |
| Validator Set Instance | (Session, Validator Set Index)               |
| Key                    | BoundedVec\<u8, 96>                          |
| ExternalAddress        | BoundedVec\<u8, 74>                          |
| Data                   | BoundedVec\<u8, 512>                         |

### Networks

Every network connected to Serai operates over a specific curve. The processor
generates a distinct set of keys per network. Beyond the key-generation itself
being isolated, the generated keys are further bound to their respective
networks via an additive offset created by hashing the network's name (among
other properties). The network's key is used for all coins on that network.

Networks are not acknowledged by the Serai network, solely by the processor.

| Network  | Curve     |
|----------|-----------|
| Bitcoin  | Secp256k1 |
| Ethereum | Secp256k1 |
| Monero   | Ed25519   |

### Coins

Coins exist over a network and have a distinct integer ID.

| Coin     | Network  | ID |
|----------|----------|----|
| Serai    | Serai    | 0  |
| Bitcoin  | Bitcoin  | 1  |
| Ether    | Ethereum | 2  |
| DAI      | Ethereum | 3  |
| Monero   | Monero   | 4  |
