# Signature Process

## Overview

This document describes the process of signing a multisignature transaction, and the messages that are used to communicate between the various Serai processes. The process is as follows:

1. The operator starts their infrastructure for the first time and unique keys are generated:
        - a new keypair for coordinator messaging.
        - a new keypair for processor messaging.
        - a new keypair for processor signature.
2. The coordinator provides its public key to `{IDENTITY}{COIN}` topic on the general parition via the `CoordinatorPublicKey` message.
3. The processor provides its public key to the `{IDENTITY}{COIN}` topic on the general partition via the `ProcessorPublicKey` message.
4. If a new pubkey is provided by the processor, the coordinator will immediately forget the previous and replace with the new key.
5. Each Processor will send a `SignerReady` message to the `{IDENTITY}{COIN}` topic on the encrypted partition.
6. Upon SignerReady, the coordinator will get a list of singers from the Serai network.
7. The coordinator will use network provided contact information to send a list of its processor message public keys to each network provided member.
8. The receiving coordinator will place each message key in the lists on the appropriate coin topic with the `ExternalPublicKeyIn` message.
9. The process consuming the `ExternalPublicKeyIn` message will then create an encrypted message targeting the external processor with the `EncryptedPublicKeyOut` message.
10. The coordinator will consume the `EncryptedPublicKeyOut` message and forward it to the appropriate external coordinator over the network connection.
11. The external coordinator will consume the `EncryptedPublicKeyOut` message and place it in the appropriate coin topic with the `EncryptedPublicKeyIn` message.
12. The process consuming the `EncryptedPublicKeyIn` message will then decrypt the message and safely store it within memory.
13. When encrypted keys are received from all members of the network, the processor will start the key generation process by producing `EncryptedKeyGenCommitmentOut` messages.
14. The coordinator will consume the `EncryptedKeyGenCommitmentOut` message and forward it to the appropriate external coordinator over the network connection.
15. The external coordinator will consume the `EncryptedKeyCommitmentOut` message and place it in the appropriate coin topic with the `EncryptedKeyGenCommitmentIn` message.
16. The process consuming the `EncryptedKeyGenCommitmentIn` message will then decrypt the message and use it to produce a `EncryptedKeyShareOut` message.
17. The coordinator will consume the `EncryptedKeyShareOut` message and forward it to the appropriate external coordinator over the network connection.
18. The external coordinator will consume the `EncryptedKeyShareOut` message and place it in the appropriate coin topic with the `EncryptedKeyShareIn` message. Many EncryptedKeyShareIn messages will be received.
19. The process consuming the `EncryptedKeyShareIn` message will then decrypt the message and place the shares into the signature machine corellated with the transaction hash of reference.
20. When all shares are received, the processor will produce a `PublicAddressAvailable` message that contains the public key and/or address information for the newly generated multisignature vault.

## Messages

### CoordinatorPublicKey

The `CoordinatorPublicKey` message is used to provide the coordinator's public key to the network. This message is sent to the {IDENTITY}{COIN} topic on the general partition.

```json
"CoordinatorPublicKey" : {
  "pubkey": "0x..."
}
```

### ProcessorPublicKey

```json

"ProcessorPublicKey : {
  "pubkey": "0x..."
}
```

### SignerReady

```json
"SignerReady" : {
  "pubkey": "0x..."
}
```
