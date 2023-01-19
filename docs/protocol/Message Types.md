# Serai Message Types

 This module contains the message types that are used to communicate between
 the various Serai processes.

 The message types are defined as enums, and each enum variant contains a
 struct that contains the data that is sent in the message.

 The structs should inherit from the `SeraiMessage` trait, which contains
 funnctions for validating the message data, and each message will container a header
 that contains information about the version, the message type, message size, and message hash.

 The message types are:
    - `SeraiBlock` - This message is sent from the observer to the
     coordinator when a new block is observed.D
    - `AckSeraiBlock` - This message is sent from the processor to
     the serai kafka topic when a block height is acknowledged.
    - `ExternalBlock{COIN}` - this message is sent from the processor to
     the relevant coin kafka topic when a block is witnessed from the XMR network.
    - `ExternalInstruction{COIN}` - the message is sent from the processor to
     the relevant coin kafka topic when an instruction is witnessed from a block.
    - `SeraiInstruction{COIN}` - this message is sent from the coordinator to the
     relevant coin topic when a new instruction is witnessed from Serai targeting the coin's network.
    - `SeraiSetUpdate` - this message is produced from the coordinator via the observer process to
     the relevant coin topics when a new set is witnessed from Serai.
    - `SeraiNetworkUpdate` - this message is produced from the coordinator via the observer process to
     the network process when a new network is witnessed from Serai.