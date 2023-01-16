# Constants

### Types

These are the list of types used to represent various properties within the
protocol.

| Alias                  | Type                           |
|------------------------|--------------------------------|
| Amount                 | u64                            |
| Coin                   | u32                            |
| Session                | u32                            |
| Validator Set Index    | u16                            |
| Validator Set Instance | (Session, Validator Set Index) |
| Key                    | Vec\<u8>                       |

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
| Bitcoin  | Bitcoin  | 0  |
| Ether    | Ethereum | 1  |
| DAI      | Ethereum | 2  |
| Monero   | Monero   | 3  |
