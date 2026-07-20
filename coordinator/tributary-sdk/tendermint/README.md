# Tendermint

An implementation of [Tendermint](https://arxiv.org/pdf/1807.04938.pdf) in
Rust.

This is not intended to be interoperable with
[CometBFT](https://github.com/cometbft/cometbft/) or to follow any pre-existing
specification of Tendermint. It is intended to be valid as a library to be
built into larger applications, with the initial use-case being to be used as
the basis for a broadcast channel with agreement on the order of messages.

### Application Layer

This library solely implements Tendermint, the protocol. It does not implement
a blockchain or peer-to-peer network, using traits to model these external
instantiations.

The blockchain is modeled with the [`Blockchain`] trait, with
[`Blockchain::add_block`] being used to add any block with a verified commit
produced by the Tendermint process. Such a block _may_ be invalid according to
[`Blockchain::validate`] however. This is a break from the specification which
will never decide on a block which was not considered valid, a break which is
accepted here. This is for two reasons:

1) This allows using the consensus process itself to vote on the semantic
   validity of blocks, which can be used to greatly optimize certain
   application-layer flows.
2) If a block is committed which is semantically invalid, either soundness
   has been violated OR the local view is faulty. As either case would be a
   clear invariant, we instead say such behavior is valid so long as the
   consumer is aware of it. Note no machine will prevote for a block it
   considers invalid, so for a network with soundness intact, this is a
   non-issue.

Despite the intended modularity, [`borsh`](https://docs.rs/borsh) is currently
used for the messages of Tendermint itself. Ideally, this would be allowed to
be any arbitrary codec in the future.

### Network Layer

The network is modeled with the [`Network`] trait, which primarily just
requires a broadcast function (with no formal properties or guarantees, though
progress will only be made as it sufficiently functions). This SHOULD be
implemented via a gossip layer, where this library's messages are signed,
allowing them to be forwarded by participants who aren't their origin.

This library will inherently rebroadcast the necessary messages to ensure
consensus does not stall after an intermittent loss of network functionality.
The implementation of the [`Network`] trait DOES NOT have to provide sequential
delivery of messages nor attempt re-delivery. This library will not broadcast
produced [`Commit`]s however, nor historical blocks, and the implementation of
syncing _to the current block_ is left entirely to the application.

### Validators

Validators are expected to be consistent throughout the execution of the
Tendermint protocol. Any consideration of validators changing, such as along an
'epoch' boundary, is excluded from and not considered by this library.

Validators are weighted, where the sum weight of validators is restricted to
the range `1 ..= u16::MAX`.

### Memory Usage

This library aims to bound its memory and storage use to be (approximately)
_linear_ to the amount of validators defined. This limits the potential chances
for this library to emit slashes (with evidence) for equivocations, though this
is accepted as detecting equivocations is inherently only possible under
certain synchrony conditions.

### Complexity

Tendermint presents as having three steps per round, where:

- Each message is of size independent to the set
- Each round is of quadratic complexity, due to the second and third steps
  having `n` validators send messages to all `n` other validators
- The amount of rounds (assuming synchrony) is bounded by the set size

This effects a consensus protocol with cubic communication complexity.

This implementation slightly differs in order to achieve its desired bounds on
memory usage. For the first step, which is generally of linear complexity as a
single proposer sends one message of size independent to the set to all other
validators, this library also includes an aggregate signature which serves as
justification for the proposal's choice of "valid round" (a historical round
which did not produce a commit but for which a sufficient amount of validators
did vote for the proposal). If the aggregate signature is naïve, and simply the
list of signatures intended to be aggregated, then this messages becomes of
size _linear_ to the set, causing this step to have quadratic complexity
(instead of linear). This is accepted as the resulting protocol maintains the
exact same complexity.

If the aggregate signature is a threshold signature, then the aggregate
signature may have size independent to the set however. This would presumably
require first running a Distributed Key Generation (DKG) protocol, where the
threshold signing protocol would have to execute in just one round
(such as with BLS signatures), and restore the original complexity for the
first step of each round (and enable producing smaller commits). Unfortunately,
a DKG generally itself requires consensus, creating a chicken-and-egg problem
(where a DKG is needed to instantiate consensus but itself requires consensus).
One solution may be to run Tendermint _without threshold signatures_ in order
to perform a DKG, before spawning a new consensus instance
_with threshold signatures_ which benefits from the increased performance.
Such strategies are out-of-scope to this library, as are the further
optimizations threshold signatures enable (consensus protocols which are of
quadratic complexity in total, not cubic).

This matters to the user as messages, as exchanged over the P2P layer, are not
of size independent to the set (without more complicated signature schemes, as
distinct from the Tendermint protocol as described). Additionally, the evidence
within slash reasons may contain an aggregate signature and suffer the same
complexity. The evidence within slash reasons does substitute any referenced
blocks with just their hashes though, making the slash reasons of size
independent to the block size (a practical optimization which may allow placing
slash reasons within blocks).

### Crash Safety

This library intends to be _sound and maintain liveness_ so long as its
database is always successfully flushed to disk upon any operations, or if the
database operation would fail, the failure effects a panic _before_ the
operation returns as completed. This is the expected failure model of the
underlying [`serai-db`](https://docs.rs/serai-db) which this library makes use
of.

On boot, this library will defer to the database to determine the state it's
continuing and the view it held during its prior instantiation. The unexpected
erasure, omission, or corruption of this database MAY cause this validator to
be considered faulty and MAY cause slashes (or exhibit undefined behavior
entirely) accordingly. The same holds true if the clock rewinds across
instances.

This library also makes no effort to detect if the specified validator is being
used by multiple processes in a way which would inherently enable
equivocations. Such behavior MAY additionally cause slashes (or exhibit
undefined behavior entirely).

Finally, this library is maintained under the
[Serai](https://github.com/serai-dex/serai) repository which has very strict
standards. Specifically, _any undocumented panic reachable from a public API_
is generally considered a security issue covered by
[Serai's Bug Bounty Program](
  https://github.com/serai-dex/serai/tree/next/SECURITY.md
). However, the implementations of traits within this library, which occurs at
time-of-compile _are assumed to be in good faith_. While the traits do
_attempt_ to clearly and explicitly document the expected bounds, intentionally
antagonistic implementations, or implementations which would break
near-immediately and not pass basic testing, will not be considered security
issues. In order to be a security issue, a _good faith_ implementation
(even if naïve) must expose a panic internal to the Tendermint process, though
antagonistic usage of the API _with correct implementations of the traits_ will
still be recognized as security issues.

One notable example of assuming the implementations are in good-faith is that
we assume serialization and deserialization are infallible unless the
underlying IO is. Additionally, we assume the database is infallible. While a
database may fail in real life, we assume that will be resolved by the process
being terminated and restarted, in a way considered entirely out-of-scope to
this library.

### Liveness under Eventual Synchrony

Tendermint is _sound_ under asynchrony yet only _live_ under synchrony. With
each round, Tendermint increases the time before it moves on to the next step
so that the time allocated to each step _eventually_ exceeds the time required
to perform each step. When such synchrony is _eventually_ obtained, then
consensus should be achieved, and the blockchain should continue to have blocks
added.

This library attempts to ensure liveness accordingly, so long as the following
properties are _eventually_ achieved for a sufficiently long period of time:

- The proposer for the current round is live.
- At any moment, at least the necessary threshold of validators is honest and
  within the synchrony bounds.
- Between moments, the validators who are honest and within the synchrony
  bounds MAY be replaced by an adversary with validators who are honest but
  _were_ outside of the synchrony bounds.
- Messages sent during one moment will be received by all validators who are
  honest and within the synchrony bound _for the next moment_.

This is intended to correspond to the model where an adversary may perform
Denial of Service attacks against up to `f` validators at a time, causing them
to appear offline, and may change who their targets are. Note we require a
somewhat weaker adversary due to requiring the adversary not be able to force
the proposer for each round offline (a single validator), which is a limitation
of Tendermint's single leader model combined with a lack of a secret single
leader election protocol.

This effort is complicated by our bounded memory usage, preventing us from
storing our entire historical message log (and the messages of all validators).
If we did so, the naïve solution of always gossiping every historical message
would be sufficient to ensure everyone has the same current view for the honest
validators. It's also complicated by how the Tendermint protocol, as described,
is amenable to bounded memory usage but is not actually described with bounded
memory usage. This library had to solve the practical problems which occur
accordingly itself, and this library's solutions have NOT been formally proven
to maintain liveness.

If such an adversary is able to cause the consensus to stall, it WILL be
considered a bug within this library. It WILL NOT be considered a security
issue according to the above bug bounty program however, even when argued as a
'network shutdown' (or similar) due to the infeasibility of such an adversary
in real life (a subject which will not be up for debate nor discussion). Due to
it being a high-severity bug however, it MAY still be eligible for a good-will
reward, at the discretion of the program's managers.

### Possibility for Redundancy

The [`Signer`] trait has an asynchronous `sign` function, allowing the sign
implementation to involve a (sufficiently low-latency) remote service. This MAY
allow ensuring any signed message is backed up in a redundant fashion as
potentially sufficient to enable recovering from a corrupted database without
being faulty. As an example of such a service (without any endorsement), please
see [Horcrux](https://github.com/straneglove-ventures/horcrux).

No such functionality is currently implemented however and the necessary API to
rebuild a local view from a outsourced log is not present. This is solely a
note on the potential for deriving a more redundant service (such as one which
even on corruption, has a log of its published messages and can therefore
ensure it does not equivocate in the future) and existing considerations
towards one. Further efforts on this topic would be appreciated.

### no-`alloc` and no-`std`

This library defines `alloc` and `std` features. With less and less of a
platform available, less efficient algorithms may be substituted. No minimum
degree of functionality, and no maximum bound on stack usage, is established
nor guaranteed.
