# Validator Sets

Validator Sets are defined at the protocol level, with the following parameters:

  - `network`                  (NetworkId): The network this validator set
                                            operates over.
  - `allocation_per_key_share` (Amount):    Amount of stake needing allocation
                                            in order to receive a key share.

### Participation in Consensus

The validator set for `NetworkId::Serai` participates in Serai's own consensus,
producing and finalizing blocks.

### Multisig

Every Validator Set is expected to form a `t`-of-`n` multisig, where `n` is the
amount of key shares in the Validator Set and `t` is `n * 2 / 3 + 1`, for each
of its networks. This multisig is secure to hold coins valued at up to 33% of
the Validator Set's allocated stake. If the coins exceed that threshold, there's
more value in the multisig and associated liquidity pool than in the
supermajority of allocated stake securing them both. Accordingly, it'd be no
longer financially secure, and it MUST reject newly added coins.

### Multisig Creation

Multisigs are created by Processors, communicating via their Coordinators.
They're then confirmed on chain via the `validator-sets` pallet. This is done by
having 100% of participants agree on the resulting group key. While this isn't
fault tolerant regarding liveliness, a malicious actor who forces a `t`-of-`n`
multisig to be `t`-of-`n-1` reduces the fault tolerance of the created multisig
which is a greater issue. If a node does prevent multisig creation, other
validators should issue slashes for it/remove it from the Validator Set
entirely.

Placing the creation on chain also solves the question of if the multisig was
successfully created or not. Processors cannot simply ask each other if they
succeeded without creating an instance of the Byzantine Generals Problem.
Placing results within a Byzantine Fault Tolerant system resolves this.

### Multisig Rotation

Please see `processor/Multisig Rotation.md` for details on the timing.

Once the new multisig publishes its first `Batch`, the old multisig's keys are
cleared and the set is considered retired. After a one-session cooldown period,
they may deallocate their stake.

### Set Keys (message)

  - `network`   (Network):   Network whose key is being set.
  - `key_pair`  (KeyPair):   Key pair being set for this `Session`.
  - `signature` (Signature): A MuSig-style signature of all validators,
                             confirming this key.
