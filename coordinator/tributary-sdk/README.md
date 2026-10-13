# Tributary SDK

The Tributary SDK is a mini-blockchain framework, intended for being embedded
into applications (and not itself the application). It serves as a
decentralized append-only message log, with agreement on the order of messages.

### Model

The Tributary is a blockchain, where blocks are appended
_once they have obtained consensus_. Messages are represented by
"transactions", where the application defines its transaction type to be
included in blocks. The Tributary does not model any state nor does it allow
checking if transactions make sense semantically within the application's
context, solely syntactically.

Once appended onto the blockchain, blocks may be read. The application is
intended to index these blocks, applying the transactions within against the
application's state and handling their semantics. If a transaction is
semantically invalid, it is up to the application to ignore it or otherwise
handle it however. This minimizes the complexity of the Tributary SDK itself,
with caveat semantically-invalid transactions must be ignored (and still take
up space) rather than being excluded from the Tributary in the first place.

Transactions are allowed to have one of three types:

- Provided: These transactions MUST be provided _by each validator_. A
  validator WILL NOT vote for a block with a provided transaction it has not
  itself provided into its state. However, if a supermajority of validators do
  achieve consensus on a block with provided transactions, even if the
  transactions were not locally provided
  _or disagree with the locally provided transactions_, the block will still be
  added to the blockchain. This means the application MUST still check the
  on-chain provided transactions are consistent with the local view.

  Each provided transaction has an assigned scope. Provided transactions only
  have to be ordered _within their scope_.

  There are no limitations on the quantity of provided transactions which may
  be held within the local state due to the assumption they're canonical items
  which the application has decided to provide.

- Unsigned: These transactions are not signed by a specific validator but may
  be broadcast through the mempool. They are given priority within the
  Tributary as they're expected to correspond to universal, 'system' messages.

- Signed: These transactions are signed by a specific validator and may be
  broadcast through the mempool.

### Consensus

The Tributary SDK achieves consensus over blocks via Tendermint, as implemented
by [`tendermint-machine`](https://docs.rs/tendermint-machine). The choice of
Tendermint enables consensus
_even in the presence of misbehaving validator_, so long as the misbehaving
validators are less than a third of all validators (by weight).

The choice of Tendermint is beneficial for its simplicity, for not requiring
any setup beyond the validators' public keys, and for being reasonably
efficient. It is suboptimal in that progress requires synchrony: for a
sufficient amount of validators to communicate within an expected timeframe.
Even if validators regularly and frequently communicate, if it's not done
within said timeframe, no agreement will be achieved.

Failure to achieve agreement linearly increases the time alotted for the next
attempt (resetting once agreement is successfully achieved). The idea of such a
timeline is fundamental to Tendermint. This means if validators are expected to
only be online occasionally, such as if the application is ran on mobile phones
and validators only connect whenever they open the app, this is not a good fit
without additional orchestration (such as having the validators first confirm
they're online before beginning a short-lived session while validators can
reasonably be assumed to be online and reachable for the entire duration of the
session).

In the future, a goal is to implement _asynchronous_ consensus, which does not
have such restrictions on timing. https://eprint.iacr.org/2024/677 would have
the same communication complexity as Tendermint (in the worst case) and would
be similarly functional (not requiring any additional setup in advance).

### Cryptography

[`tendermint-machine`](https://docs.rs/tendermint-machine) is abstract to the
cryptography it's instantiated with. The Tributary SDK explicitly uses Schnorr
signatures over Ristretto though, not just for the Tendermint consensus
protocol but also for its signed transactions. This makes it efficient but
means it is vulnerable to quantum computers. Propagating the choice of
cryptography is an open task.

### Slashing and Censuring

Validators may be _slashed_ by the Tendermint consensus process for
misbehavior _with evidence_. These slashes are included in blocks, ensuring
everyone observes them with agreement on when they occurred. Slashed validators
are not allowed to propose blocks nor publish signed transactions, effectively
being removed from the Tributary.

For slashes without evidence, _censuring_ is used instead. Censures lack
evidence, agreement on when the censure occurs, allowing any participant to
censure any validator upon any local observation of misbehavior (regardless of
when it occurs or if there's evidence to justify it). A validator will not vote
for censured validators' block proposals nor populate their signed transactions
within their mempools.

The application layer is enabled to censure validators. While the application
layer may have evidence of misbehavior, the lack of agreement on _when_ the
misbehavior occurred (due to the asynchrony between the Tributary proper and
the application which indexes it) prevents emitting slashes.

### Other Notes

- The Tributary SDK makes use of [`borsh`](https://docs.rs/borsh) internally
  for certain encodings, and it abstracts over a database via the usage of
  [`serai-db`](https://docs.rs/serai-db).

- The networking layer is abstract. Serai, who maintains this library at this
  time, makes use of [LibP2P](https://libp2p.io) for its networking. Direct
  peer-to-peer channels or other networking solutions may be used instead, but
  latent or erratic networking solutions SHOULD NOT be used due to the
  Tendermint consensus's required bounds on synchrony.

- The Tributary SDK was designed to be minimal, and in doing so, may be missing
  desired functionality. Several items are already noted as available to be
  improved upon. It is available for public consumption however in case it may
  of benefit to others, and contributions are welcome.

- For more context on integration, please read
  [`tendermint-machine`'s documentation](https://docs.rs/tendermint-machine).

- Up to 65,535 validators are supported ([`u16::MAX`]). Despite that, due to
  algorithmic complexities and practical inefficiencies, large validator sets
  likely SHOULD NOT be used. No representations of this library's performance
  with large validator sets are made.

- This library is intended to eventually be covered under
  [Serai's Bug Bounty Program](https://immunefi.com/bounty/serai). When so
  included, the same good-faith expectations and general practices established
  for [`tendermint-machine`](https://docs.rs/tendermint-machine) will also be
  applied here.
