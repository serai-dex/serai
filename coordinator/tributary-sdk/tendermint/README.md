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

### no-`alloc` and no-`std`

This library defines `alloc` and `std` features. With less and less of a
platform available, less efficient algorithms may be substituted. No minimum
degree of functionality, and no maximum bound on stack usage, is established
nor guaranteed.
