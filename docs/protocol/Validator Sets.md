# Validator Sets

Validator Sets are defined at the protocol level, with the following parameters:

  - `bond`         (Amount):             Amount of bond per key-share.
  - `network`      (Network):            The network this validator set operates
                                         over.
  - `participants` (Vec\<SeraiAddress>): List of participants within this set.

Validator Sets are referred to by `NetworkId` yet have their data accessible via
`ValidatorSetInstance`.

### Participation in consensus

All Validator Sets participate in consensus. In the future, a dedicated group
to order Serai is planned.

### Multisig

Every Validator Set is expected to form a `t`-of-`n` multisig, where `n` is the
amount of key shares in the Validator Set and `t` is `n * 2 / 3 + 1`, for each
of its networks. This multisig is secure to hold coins up to 67% of the
Validator Set's bonded value. If the coins exceed that threshold, there's more
value in the multisig than in the supermajority of bond that must be put forth
to control it. Accordingly, it'd be no longer financially secure, and it MUST
reject newly added coins which would cross that threshold.

### Multisig Creation

Multisigs are created by processors, communicating via their Coordinators.
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

### Multisig Lifetime

The keys for a Validator Set remain valid until its participants change. If a
Validator Set adds a new member, and then they leave, the set's historical keys
are not reused.

### Multisig Handoffs

Once new keys are confirmed for a given Validator Set, they become tracked and
the recommended set of keys for incoming coins. The old keys are still eligible
to receive coins for a provided grace period, requiring the current Validator
Set to track both sets of keys. The old keys are also prioritized for handling
outbound transfers, until the end of the grace period, at which point they're
no longer eligible to receive coins and they forward all of their coins to the
new set of keys. It is only then that validators in the previous instance of the
set, yet not the current instance, may unbond their stake.

### Set Keys (message)

  - `network`   (Network):   Network whose key is being voted for.
  - `key_pair`  (KeyPair):   Key pair being set for this `Session`.
  - `signature` (Signature): A MuSig-style signature of all validators,
confirming this key.

Once a key is voted on by every member, it's adopted as detailed above.
