# Validator Sets

Validator Sets are defined at the protocol level, with the following parameters:

  - `bond`         (Amount):     Amount of bond per key-share.
  - `coins`        (Vec\<Coin>): List of coins within this set.
  - `participants` (Vec\<Coin>): List of participants within this set.

Validator Sets are referred to by `ValidatorSetIndex` yet have their data
accessible via `ValidatorSetInstance`.

At launch, there will solely be Validator Set 1, managing Bitcoin, Ether, DAI,
and Monero.

### Participation in the BFT process

All Validator Sets participate in the BFT process described under
[Consensus](./Consensus.md). Specifically, a block containing In Instructions
for a coin must be approved by the BFT majority of the Validator Set responsible
for it, along with the BFT majority of the network by bond.

At this time, In Instructions for a coin are only expected to be included when a
validator from the Validator Set managing the coin is the producer of the block
in question.

Since there is currently only one Validator Set, the aforementioned BFT
conditions collapse to simply the BFT majority by bond. Ensuring BFT majority
per responsible Validator Set is accordingly unimplemented for now.

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
fault tolerant, a malicious actor who forces a `t`-of-`n` multisig to be
`t`-of-`n-1` reduces the fault tolerance of the multisig which is a greater
issue. If a node does prevent multisig creation, other validators should issue
slashes for it/remove it from the Validator Set entirely.

Due to the fact multiple key generations may occur to account for
faulty/malicious nodes, voting on multiple keys for a single coin is allowed,
with the first key to be confirmed becoming the key for that coin.

Placing it on chain also solves the question of if the multisig was successfully
created or not. Processors cannot simply ask each other if they succeeded
without creating an instance of the Byzantine Generals Problem. Placing results
within a Byzantine Fault Tolerant system resolves this.

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

### Vote (message)

  - `coin` (Coin): Coin whose key is being voted for.
  - `key`  (Key):  Key being voted on.

Once a key is voted on by every member, it's adopted as detailed above.
