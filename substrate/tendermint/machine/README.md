# Tendermint

An implementation of the Tendermint state machine in Rust.

This is solely the state machine, intended to be mapped to any arbitrary system.
It supports an arbitrary signature scheme, weighting, and block definition
accordingly. It is not intended to work with the Cosmos SDK, solely to be an
implementation of the [academic protocol](https://arxiv.org/pdf/1807.04938.pdf).

### Caveats

- Only SCALE serialization is supported currently. Ideally, everything from
  SCALE to borsh to bincode would be supported. SCALE was chosen due to this
  being under Serai, which uses Substrate, which uses SCALE. Accordingly, when
  deciding which of the three (mutually incompatible) options to support...

- tokio is explicitly used for the asynchronous task which runs the Tendermint
  machine. Ideally, `futures-rs` would be used enabling any async runtime to be
  used.

- It is possible for `add_block` to be called on a block which failed (or never
  went through in the first place) validation. This is a break from the paper
  which is accepted here. This is for two reasons.

  1) Serai needing this functionality.
  2) If a block is committed which is invalid, either there's a malicious
     majority now defining consensus OR the local node is malicious by virtue of
     being faulty. Considering how either represents a fatal circumstance,
     except with regards to system like Serai which have their own logic for
     pseudo-valid blocks, it is accepted as a possible behavior with the caveat
     any consumers must be aware of it. No machine will vote nor precommit to a
     block it considers invalid, so for a network with an honest majority, this
     is a non-issue.

### Paper

The [paper](https://arxiv.org/abs/1807.04938) describes the algorithm with
pseudocode on page 6. This pseudocode isn't directly implementable, nor does it
specify faulty behavior. Instead, it's solely a series of conditions which
trigger events in order to successfully achieve consensus.

The included pseudocode segments can be minimally described as follows:

```
01-09 Init
10-10 StartRound(0)
11-21 StartRound
22-27 Fresh proposal
28-33 Proposal building off a valid round with prevotes
34-35 2f+1 prevote -> schedule timeout prevote
36-43 First proposal with prevotes -> precommit Some
44-46 2f+1 nil prevote -> precommit nil
47-48 2f+1 precommit -> schedule timeout precommit
49-54 First proposal with precommits -> finalize
55-56 f+1 round > local round, jump
57-60 on timeout propose
61-64 on timeout prevote
65-67 on timeout precommit
```

The corresponding Rust code implementing these tasks are marked with their
related line numbers.
