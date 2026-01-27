# Serai Validator Sets Pallet

The Serai blockchain, built upon the Substrate framework, specifically exists
to fulfill two purposes within the Serai project:

- The selection and organization of validators
- The ordering of swaps

This pallet is responsible for the first purpose. It handles validators
declaring themselves, selecting validators for new sessions, and session
rotation.

### Validator Sets

For each network integrated into Serai, and the Serai network itself, there is
a dedicated set of validators. These sets have independently-defined
validators, which may or may not overlap, and rotate independently. This is
intended to allow individual validators to choose which networks they want to
validate for (and run the software of) and to scale in a more horizontal
fashion. While each validator set has a bounded amount of validators, the total
amount of validators on the Serai network is bounded by _the product of_ the
limit per set and the amount of networks.

This does not mean Serai itself horizontally scales in all regards. Its
singular Substrate blockchain is still of bounded capacity. To compensate for
this, validator sets do _most_ operations off-chain, only publishing results as
necessary on-chain.

When a validator set wants to publish a message onto Serai's Substrate
blockchain, it generally signs the message with a declared oraclization key.
The oraclization key is a standard Ristretto public key and signatures from it
may be verified _independently of the amount of validators present within the
validator set_. This is due to _off-chain multi-party protocols_ being used for
the validator set to produce the expected signatures, instead of using a scheme
such as on-chain voting to approve messages (incurring an on-chain complexity
linear to the amount of validators in the set).

In order to declare the oraclization key, which is expected to be the result of
a Distributed Key Generation (DKG) protocol, the validators do have to agree on
the key using solely their existing keys (as a newly created key cannot be used
to authenticate itself). For this, Serai employs a single use of an on-chain
threshold signature scheme (with complexity linear to the amount of the
validators participating). Specifically, the key is published with a bit vector
of the validators who are participating in the signature authenticating it.
Then, these validators have their keys aggregated with
[MuSig](https://eprint.iacr.org/2020/1261), before the resulting aggregate key
is verified against the produced aggregate signature. While this only involves
a single signature, the key aggregation process requires communicating a linear
amount of bits and performing a multi-scalar multiplication with a linear
amount of terms.

Authenticating the oraclization key is allowed to be down by only a threshold
of the participating validators to ensure the process is robust. A single
validator being offline _MUST NOT_ be able to stall the entire validator set.
Traditionally, this would raise the risk that the offline validators could be
excluded from the DKG, perhaps if privately sent invalid secret shares which
are unusable. To ensure this isn't a risk, Serai designed a novel
publicly-verifiable encryption scheme which allows the online participants to
verify the integrity of the (alleged) secret shares encrypted to offline
participants. For more information, please see our
[audit statement](/audits/crypto/dkg/evrf).

With the publication of the oraclization key, as necessary to interact with
Serai, each validator set for an external network is also expected to publish
an external key (an opaque byte vector) which is usable to interact with the
validators on the network they're validating for (e.g. an encoding of an
Ethereum address).

The validator set for the Serai network itself does not need to and does not
perform these key generation/publication protocols.

### Rotation Scheduling

This pallet is tightly bound to [`pallet-babe`] and [`pallet-grandpa`], the
intended block production and finalization protocols for the Serai protocol.
BABE requires rotations occur on a specific schedule, which this pallet defers
to for when to rotate the Serai validator set _as well as all other validator
sets_. The rotations themselves are staggered to minimize the computational
cost upon any individual block however.

Rotations for an external network's validator set may not occur if there is an
issue deciding the next set, such as when the prior-decided next set still has
yet to become the current set. In this case, while the attempted rotation will
not occur, no consideration will be given to it, and the next attempted
rotation will still happen only according to the traditional schedule (the
rotation will not be re-attempted once the barriers resolve or on a more
frequent basis).

If a rotation occurs, the next set's validators are decided. When a validator
set for an external network, the newly declared validator set is now able to
publish their keys onto Serai. Eventually, they are expected to accept a
handover of responsibilities from the prior set (after some undefined off-chain
operations, generally the transferring of coins from the old validator set to
the new validator set's declared external key), which declares them the current
set.

The prior set remains active to [publish a slash report](#slashing) before
being retired.

### Validator Selection

Validators for a network are selected by the amount of stake they've allocated
to said network. A validator which does not want to validate for a specific
network simply does not have to allocate stake to that network.

In order for a validator to allocate stake to any network, the validator must
first set their auxiliary keys for the Serai network. The auxiliary key will be
the key the validator uses to operate their validator, separating the key which
controls the allocation of stake from the key which is actively online.

In order for a validator to allocate stake to an external network, the
validator must first set their auxiliary keys for the external network as well.
These auxiliary keys represent elliptic curve keys over an embedded elliptic
curve, as relevant to the external network in question, and are used as part of
the DKG protocols for the oraclization/external keys.

### Auxiliary Keys

Auxiliary keys are signed by the validator which uses them, by virtue of them
being published within a signed transaction, and the keys themselves are
bundled with a Proof of Knowledge which asserts their validity and ensures the
validator using them actually is able to use them (to at least a minimal
degree). These proofs are Schnorr signatures, as used to sign transactions,
which Substrate traditionally uses a host function for signature (as performing
cryptography within the runtime is sufficiently slow it is generally preferable
to use native code instead). As these proofs are simple (they're Schnorr
signatures, not ZK-STARKs for a blockchain's state transition function) and are
infrequent (only used when declaring a validator, not with every transaction),
Serai does not require nor does it employ host functions for their
verification, preferring the simplicity and determinism guarantees offered by
remaining within the runtime.

Auxiliary keys arguably take the same role within the Serai runtime as
"Session Keys" traditionally does within a Substrate runtime. One distinction
is that Session Keys aim to declare a key per purpose, while Serai solely
declares keys per network (for which it may serve many purposes). This is
possible for the Serai network specifically as Serai has homogenized the
cryptography within its protocol (with regards to consensus and so on) to
solely make use of Ristretto.

As for using a single key, this removes the independent domains inherently
offered by independent keys. The Serai protocol applies an account derivation
scheme to product subkeys for each intended usage, as enabled by our choice of
cryptography (key-binding Schnorr signatures) not being malleable with regards
to the key signed with. It should be noted however that _any_ subkey can be
used to recover the root key _and all other subkeys_. This prohibits a
theoretical construction of a BABE process which, if compromised, does not
threaten the integrity of the same validator's GRANDPA process. Due to how
niche such a deployment would be, this is accepted.

### Validator Deallocation

Validators are allowed to deallocate stake from a network. The deallocation is
delayed until the validator is no longer active, plus an additional session to
allow for a response to any misbehavior which occurred during their activity.

### Distribution of Rewards

Rewards are distributed directly to a validator's allocated stake. This not
only increases Serai's security as rewards are distributed but also makes
rewards subject to allocated stake's deallocation timeline, allowing them to be
slashed if/as necessary.

### Slashing

As a general policy, inactivity is _not_ a reason to slash a validator due to
the potential for _any_ validator to be disconnected under an asynchronous
network through no fault of their own. While Serai as a whole is not modeled
under an asynchronous network, it is a long-term goal. Validators are expected
to only be rewarded upon activity however, still ensuring incentives are for
operating within normal parameters (and not distributed to offline nodes).

For external validator sets, where slashing occurs in response to off-chain
misbehavior, validator sets are expected to publish a slash report. The slash
report is signed by, and therefore authenticated by, the validator set's
oraclization key. Due to the lack of explicit evidence, validated on-chain,
this does introduce a trust assumption that the external validator set is
behaving honestly. As a dishonest validator set can always misbehave in a way
representing an unattributable compromise of all expected operations, deserving
a slash for all associated stake, this is not considered in a reduction of the
trust assumptions.

For Serai's validator set, an inherent transaction (with a reason specified as
an opaque byte vector) can be used to fatally slash any individual Serai
validator. This defers on-chain verification of BABE/GRANDPA equivocation
proofs for off-chain validation via the traditional inherent transaction
pipeline. The allowance to specify an opaque byte vector as the reason still
allows embedding such proofs on-chain however, allowing any individual to
verify the justification for the slash. The reason for not validating the
proofs themselves directly on-chain is to not tightly bind to BABE/GRANDPA's
formatting of equivocation proofs, allowing future flexibility with how the
protocol is defined.
